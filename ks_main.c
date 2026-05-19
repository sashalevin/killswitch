// SPDX-License-Identifier: GPL-2.0
/*
 * Per-function short-circuit mitigation (out-of-tree module).
 *
 * Copyright (C) 2026 Sasha Levin <sashal@kernel.org>
 *
 * Engaging a killswitch installs a kprobe at the function's entry whose
 * pre-handler sets the return register and skips the body via the
 * per-arch ks_override_function_with_return().  Operator interface lives
 * at /sys/kernel/security/killswitch/.
 *
 * This is the out-of-tree variant of kernel/killswitch.c.  Differences
 * from the upstream patch:
 *
 *   - TAINT_KILLSWITCH is not added.  The module loader sets
 *     TAINT_OOT_MODULE ('O') automatically; the securityfs `taint` file
 *     reports that bit.
 *   - LOCKDOWN_KILLSWITCH is not added.  Runtime engage is gated by
 *     LOCKDOWN_KPROBES, which register_kprobe() also enforces.
 *   - The "killswitch=" boot parameter is replaced by the module
 *     parameter `engage`, applied at module_init.  Use
 *     /etc/modprobe.d/killswitch.conf for fleet rollout.
 *   - override_function_with_return() is not exported by any kernel,
 *     so we ship and call a renamed copy: ks_override_function_with_return().
 */

#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kprobes.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/panic.h>
#include <linux/percpu.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>
#include <linux/umh.h>

#include "ks_internal.h"

/*
 * tryengage probes a function for T seconds before committing.  Until
 * the timer fires, the kprobe is installed but the pre-handler only
 * counts calls; if anything called the function during the probe
 * window we abort, otherwise we flip to engaged.  Same kprobe, no
 * gap between probe and engagement.
 */
enum ks_state {
	KS_PROBING,
	KS_ENGAGED,
};

struct ks_attr {
	struct list_head	list;
	struct kprobe		kp;
	/* atomic so a writer racing an in-flight call can't tear the long. */
	atomic_long_t		retval;
	/* false once disengaged; per-fn file ops then return -EIDRM. */
	bool			engaged;
	/* enum ks_state; read lockless from the pre-handler. */
	atomic_t		state;
	unsigned long __percpu	*hits;
	struct dentry		*dir;
	/* jiffies; only meaningful while state == KS_PROBING. */
	unsigned long		probe_deadline;
	/* seconds; for the audit/log line on commit/abort. */
	unsigned int		probe_timeout;
	/* fires once T seconds after tryengage; pinned to ks_lock. */
	struct delayed_work	commit_work;
	/* engaged_list holds one ref; each open per-fn fd holds one;
	 * a pending commit_work holds one more.
	 */
	struct kref		refcnt;
};

#define KS_TRY_MAX_SECONDS	86400U	/* 24h ceiling on T */

/*
 * engagebpf opens the BPF verifier's ALLOW_ERROR_INJECTION gate by
 * engaging an internal killswitch on within_error_injection_list with
 * retval=1, spawns the userspace helper that loads the BPF program,
 * and disengages once the helper returns.  The window is exactly the
 * duration of the helper's BPF load syscall.
 */
#define KS_WHITELIST_GATE	"within_error_injection_list"
#define KS_BPF_HELPER_PATH	"/usr/sbin/ks-bpf-load"

static void ks_commit_work_fn(struct work_struct *work);
static int __ks_disengage(const char *symbol);

static DEFINE_MUTEX(ks_lock);
static LIST_HEAD(ks_engaged_list);
/*
 * Set in killswitch_exit() before the engaged list is drained, under
 * ks_lock.  Any __ks_install() call that arrives after that sees the
 * flag and refuses to register a kprobe or schedule a commit_work,
 * so module text never gets new references after the unload snapshot.
 */
static bool ks_unloading;
static struct dentry *ks_root_dir;
static struct dentry *ks_fn_dir;	/* parent for per-fn directories */

static char *engage;
module_param(engage, charp, 0444);
MODULE_PARM_DESC(engage,
	"comma-separated fn=retval list applied at module load, "
	"e.g. engage=af_alg_sendmsg=-1,ksmbd_smb2_negotiate=-22");

/* ------------------------------------------------------------------ *
 * Pre-handler: the actual override                                   *
 * ------------------------------------------------------------------ */

static int ks_kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
	struct ks_attr *attr = container_of(kp, struct ks_attr, kp);

	this_cpu_inc(*attr->hits);
	if (atomic_read(&attr->state) != KS_ENGAGED)
		return 0;	/* probe mode: count only, let the call run */
	regs_set_return_value(regs, (unsigned long)atomic_long_read(&attr->retval));
	ks_override_function_with_return(regs);
	return 1;
}
NOKPROBE_SYMBOL(ks_kprobe_pre_handler);

/* Defined non-NULL so the kprobe layer keeps the IPMODIFY ops. */
static void ks_kprobe_post_handler(struct kprobe *kp, struct pt_regs *regs,
				   unsigned long flags)
{
}

/* ------------------------------------------------------------------ *
 * Attribute lifecycle                                                *
 * ------------------------------------------------------------------ */

static struct ks_attr *ks_attr_lookup(const char *symbol)
{
	struct ks_attr *attr;

	list_for_each_entry(attr, &ks_engaged_list, list)
		if (!strcmp(attr->kp.symbol_name, symbol))
			return attr;
	return NULL;
}

static unsigned long ks_attr_hits(const struct ks_attr *attr)
{
	unsigned long total = 0;
	int cpu;

	for_each_possible_cpu(cpu)
		total += *per_cpu_ptr(attr->hits, cpu);
	return total;
}

static void ks_attr_destroy(struct ks_attr *attr)
{
	if (!attr)
		return;
	free_percpu(attr->hits);
	kfree(attr->kp.symbol_name);
	kfree(attr);
}

static void ks_attr_kref_release(struct kref *kref)
{
	ks_attr_destroy(container_of(kref, struct ks_attr, refcnt));
}

static void ks_attr_get(struct ks_attr *attr)
{
	kref_get(&attr->refcnt);
}

static void ks_attr_put(struct ks_attr *attr)
{
	kref_put(&attr->refcnt, ks_attr_kref_release);
}

static struct ks_attr *ks_attr_alloc(const char *symbol)
{
	struct ks_attr *attr;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	if (!attr)
		return NULL;

	attr->kp.symbol_name = kstrdup(symbol, GFP_KERNEL);
	if (!attr->kp.symbol_name)
		goto err;

	attr->hits = alloc_percpu(unsigned long);
	if (!attr->hits)
		goto err;

	attr->kp.pre_handler = ks_kprobe_pre_handler;
	attr->kp.post_handler = ks_kprobe_post_handler;
	INIT_LIST_HEAD(&attr->list);
	atomic_set(&attr->state, KS_ENGAGED);
	INIT_DELAYED_WORK(&attr->commit_work, ks_commit_work_fn);
	kref_init(&attr->refcnt);
	return attr;

err:
	ks_attr_destroy(attr);
	return NULL;
}

/* ------------------------------------------------------------------ *
 * Securityfs: per-fn attribute files                                 *
 * ------------------------------------------------------------------ */

/*
 * Look up by symbol name (the parent dentry's basename) under ks_lock
 * and confirm attr->dir is the file's parent dentry.  This binds the fd
 * to the engagement it was opened against and avoids dereferencing
 * inode->i_private, which a racing disengage may have freed.  d_parent
 * is stable for the open's lifetime via the file's dentry reference.
 */
static int ks_attr_open(struct inode *inode, struct file *file)
{
	struct dentry *parent = file->f_path.dentry->d_parent;
	const char *name = parent->d_name.name;
	struct ks_attr *attr;

	mutex_lock(&ks_lock);
	attr = ks_attr_lookup(name);
	if (attr && attr->dir == parent)
		ks_attr_get(attr);
	else
		attr = NULL;
	mutex_unlock(&ks_lock);
	if (!attr)
		return -ENOENT;
	file->private_data = attr;
	return 0;
}

static int ks_attr_release(struct inode *inode, struct file *file)
{
	ks_attr_put(file->private_data);
	file->private_data = NULL;
	return 0;
}

/* Caller must hold ks_lock. */
static int ks_attr_check_live(const struct ks_attr *attr)
{
	return attr->engaged ? 0 : -EIDRM;
}

static ssize_t ks_retval_read(struct file *file, char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	struct ks_attr *attr = file->private_data;
	char buf[32];
	long val;
	int ret, len;

	mutex_lock(&ks_lock);
	ret = ks_attr_check_live(attr);
	val = atomic_long_read(&attr->retval);
	mutex_unlock(&ks_lock);
	if (ret)
		return ret;
	len = scnprintf(buf, sizeof(buf), "%ld\n", val);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static ssize_t ks_retval_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	struct ks_attr *attr = file->private_data;
	char buf[32];
	long val;
	int ret;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	strim(buf);

	ret = kstrtol(buf, 0, &val);
	if (ret)
		return ret;

	mutex_lock(&ks_lock);
	ret = ks_attr_check_live(attr);
	if (!ret)
		atomic_long_set(&attr->retval, val);
	mutex_unlock(&ks_lock);

	return ret ? ret : count;
}

static const struct file_operations ks_retval_fops = {
	.open		= ks_attr_open,
	.release	= ks_attr_release,
	.read		= ks_retval_read,
	.write		= ks_retval_write,
	.llseek		= default_llseek,
};

static ssize_t ks_hits_read(struct file *file, char __user *ubuf,
			    size_t count, loff_t *ppos)
{
	struct ks_attr *attr = file->private_data;
	char buf[32];
	unsigned long hits;
	int ret, len;

	mutex_lock(&ks_lock);
	ret = ks_attr_check_live(attr);
	hits = ks_attr_hits(attr);
	mutex_unlock(&ks_lock);
	if (ret)
		return ret;
	len = scnprintf(buf, sizeof(buf), "%lu\n", hits);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations ks_hits_fops = {
	.open		= ks_attr_open,
	.release	= ks_attr_release,
	.read		= ks_hits_read,
	.llseek		= default_llseek,
};

static ssize_t ks_state_read(struct file *file, char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	struct ks_attr *attr = file->private_data;
	const char *s;
	int ret;

	mutex_lock(&ks_lock);
	ret = ks_attr_check_live(attr);
	s = atomic_read(&attr->state) == KS_ENGAGED ? "engaged\n" : "probing\n";
	mutex_unlock(&ks_lock);
	if (ret)
		return ret;
	return simple_read_from_buffer(ubuf, count, ppos, s, strlen(s));
}

static const struct file_operations ks_state_fops = {
	.open		= ks_attr_open,
	.release	= ks_attr_release,
	.read		= ks_state_read,
	.llseek		= default_llseek,
};

static ssize_t ks_timeout_left_read(struct file *file, char __user *ubuf,
				    size_t count, loff_t *ppos)
{
	struct ks_attr *attr = file->private_data;
	char buf[32];
	unsigned long left = 0;
	int ret, len;

	mutex_lock(&ks_lock);
	ret = ks_attr_check_live(attr);
	if (!ret && atomic_read(&attr->state) == KS_PROBING) {
		unsigned long now = jiffies;
		if (time_after(attr->probe_deadline, now))
			left = jiffies_to_msecs(attr->probe_deadline - now) / 1000;
	}
	mutex_unlock(&ks_lock);
	if (ret)
		return ret;
	len = scnprintf(buf, sizeof(buf), "%lu\n", left);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations ks_timeout_left_fops = {
	.open		= ks_attr_open,
	.release	= ks_attr_release,
	.read		= ks_timeout_left_read,
	.llseek		= default_llseek,
};

static int ks_create_attr_dir(struct ks_attr *attr)
{
	struct dentry *d;

	attr->dir = securityfs_create_dir(attr->kp.symbol_name, ks_fn_dir);
	if (IS_ERR(attr->dir))
		return PTR_ERR(attr->dir);

	/* ks_attr_open looks the attr up by name; i_private is unused. */
	d = securityfs_create_file("retval", 0600, attr->dir,
				   NULL, &ks_retval_fops);
	if (IS_ERR(d))
		goto err;
	d = securityfs_create_file("hits", 0400, attr->dir,
				   NULL, &ks_hits_fops);
	if (IS_ERR(d))
		goto err;
	d = securityfs_create_file("state", 0400, attr->dir,
				   NULL, &ks_state_fops);
	if (IS_ERR(d))
		goto err;
	d = securityfs_create_file("timeout_left", 0400, attr->dir,
				   NULL, &ks_timeout_left_fops);
	if (IS_ERR(d))
		goto err;
	return 0;
err:
	securityfs_remove(attr->dir);
	attr->dir = NULL;
	return PTR_ERR(d);
}

/* ------------------------------------------------------------------ *
 * Engage / tryengage / disengage                                     *
 * ------------------------------------------------------------------ */

/*
 * Common teardown for an engaged or probing entry.  Caller holds
 * ks_lock and still holds the engaged_list reference on the attr (the
 * caller drops it after this returns).
 *
 * Cancels any pending probe timer.  If cancel_delayed_work() returns
 * true we got it before it ran and must drop the timer's ref here;
 * otherwise the work is either done or blocked on ks_lock behind us
 * and will drop its own ref when it sees attr->engaged == false.
 */
static void ks_attr_tear_down_locked(struct ks_attr *attr)
{
	if (cancel_delayed_work(&attr->commit_work))
		ks_attr_put(attr);

	unregister_kprobe(&attr->kp);
	attr->engaged = false;
	list_del(&attr->list);
	securityfs_remove(attr->dir);
}

/*
 * Shared body for engage / tryengage.  When timeout_s == 0 the entry
 * goes straight to KS_ENGAGED; otherwise it starts in KS_PROBING and a
 * delayed_work is scheduled to commit or abort after timeout_s seconds.
 */
static int __ks_install(const char *symbol, long retval,
			unsigned int timeout_s, bool from_modparam)
{
	struct ks_attr *attr;
	bool probing = (timeout_s > 0);
	int ret;

	if (!symbol || !*symbol)
		return -EINVAL;
	if (timeout_s > KS_TRY_MAX_SECONDS)
		return -EINVAL;

	if (!from_modparam) {
		ret = security_locked_down(LOCKDOWN_KPROBES);
		if (ret)
			return ret;
	}

	mutex_lock(&ks_lock);

	if (ks_unloading) {
		ret = -ENXIO;
		goto out_unlock;
	}

	if (ks_attr_lookup(symbol)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	attr = ks_attr_alloc(symbol);
	if (!attr) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	atomic_long_set(&attr->retval, retval);
	atomic_set(&attr->state, probing ? KS_PROBING : KS_ENGAGED);
	attr->probe_timeout = timeout_s;
	attr->probe_deadline = probing ? jiffies + timeout_s * HZ : 0;

	ret = register_kprobe(&attr->kp);
	if (ret) {
		pr_warn("killswitch: register_kprobe(%s) failed: %d\n",
			symbol, ret);
		ks_attr_put(attr);
		goto out_unlock;
	}

	ret = ks_create_attr_dir(attr);
	if (ret) {
		unregister_kprobe(&attr->kp);
		ks_attr_put(attr);
		goto out_unlock;
	}

	list_add_tail(&attr->list, &ks_engaged_list);
	attr->engaged = true;

	if (probing) {
		ks_attr_get(attr);	/* ref handed to the commit_work */
		schedule_delayed_work(&attr->commit_work, timeout_s * HZ);
	}

	if (from_modparam) {
		pr_warn("killswitch: %s %s=%ld%s source=modparam\n",
			probing ? "tryengage" : "engage",
			symbol, retval,
			probing ? " timeout=" : "");
		if (probing)
			pr_warn("killswitch: tryengage %s timeout=%us\n",
				symbol, timeout_s);
	} else if (probing) {
		pr_warn("killswitch: tryengage %s=%ld timeout=%us uid=%u auid=%u ses=%u comm=%s\n",
			symbol, retval, timeout_s,
			from_kuid(&init_user_ns, current_uid()),
			from_kuid(&init_user_ns, audit_get_loginuid(current)),
			audit_get_sessionid(current),
			current->comm);
	} else {
		pr_warn("killswitch: engage %s=%ld uid=%u auid=%u ses=%u comm=%s\n",
			symbol, retval,
			from_kuid(&init_user_ns, current_uid()),
			from_kuid(&init_user_ns, audit_get_loginuid(current)),
			audit_get_sessionid(current),
			current->comm);
	}
	ret = 0;

out_unlock:
	mutex_unlock(&ks_lock);
	return ret;
}

static int __ks_engage(const char *symbol, long retval, bool from_modparam)
{
	return __ks_install(symbol, retval, 0, from_modparam);
}

static int killswitch_engage(const char *symbol, long retval)
{
	return __ks_engage(symbol, retval, false);
}

static int __ks_tryengage(const char *symbol, long retval, unsigned int timeout_s)
{
	return __ks_install(symbol, retval, timeout_s, false);
}

/*
 * engagebpf:  open the BPF verifier's ALLOW_ERROR_INJECTION gate just
 * long enough to load + attach a BPF override targeting an arbitrary
 * kernel function.  The window is mechanically exactly the helper's
 * blocking BPF_PROG_LOAD syscall: we engage on KS_WHITELIST_GATE,
 * synchronously run /usr/sbin/ks-bpf-load (which calls libbpf's load
 * + attach + pin), then disengage.
 */
static int __ks_engagebpf(const char *fn, const char *bpf_path)
{
	char *envp[3];
	char *load_argv[4];
	int helper_rc;
	int ret;

	if (!fn || !*fn || !bpf_path || !*bpf_path)
		return -EINVAL;

	/* Refuse if the operator already engaged the gate by hand — we
	 * don't fight a pre-existing engagement we didn't set up. */
	mutex_lock(&ks_lock);
	if (ks_unloading) {
		mutex_unlock(&ks_lock);
		return -ENXIO;
	}
	if (ks_attr_lookup(KS_WHITELIST_GATE)) {
		mutex_unlock(&ks_lock);
		return -EBUSY;
	}
	mutex_unlock(&ks_lock);

	/* Engage the gate via the normal install path so the audit
	 * trail, refcount, and securityfs surface are consistent with
	 * an operator-driven engage. */
	ret = __ks_install(KS_WHITELIST_GATE, 1, 0, false);
	if (ret) {
		pr_warn("killswitch: engagebpf %s: gate engage failed: %d\n",
			fn, ret);
		return ret;
	}

	envp[0] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
	envp[1] = "HOME=/";
	envp[2] = NULL;

	load_argv[0] = (char *)KS_BPF_HELPER_PATH;
	load_argv[1] = (char *)bpf_path;
	load_argv[2] = (char *)fn;
	load_argv[3] = NULL;

	helper_rc = call_usermodehelper(KS_BPF_HELPER_PATH,
					load_argv, envp, UMH_WAIT_PROC);

	{
		int dis = __ks_disengage(KS_WHITELIST_GATE);
		if (dis)
			pr_warn("killswitch: engagebpf %s: gate disengage failed: %d\n",
				fn, dis);
	}

	pr_warn("killswitch: engagebpf %s bpf=%s rc=%d uid=%u auid=%u ses=%u comm=%s\n",
		fn, bpf_path, helper_rc,
		from_kuid(&init_user_ns, current_uid()),
		from_kuid(&init_user_ns, audit_get_loginuid(current)),
		audit_get_sessionid(current),
		current->comm);

	return helper_rc ? -EIO : 0;
}

/*
 * Probe timer callback: T seconds after tryengage, decide commit or
 * abort by looking at the per-cpu hits counter.
 */
static void ks_commit_work_fn(struct work_struct *work)
{
	struct ks_attr *attr = container_of(work, struct ks_attr,
					    commit_work.work);
	unsigned long hits;

	mutex_lock(&ks_lock);

	if (!attr->engaged ||
	    atomic_read(&attr->state) != KS_PROBING)
		goto out;	/* disengaged or already mutated */

	hits = ks_attr_hits(attr);
	if (hits > 0) {
		pr_warn("killswitch: tryengage %s aborted: hits=%lu during %us probe\n",
			attr->kp.symbol_name, hits, attr->probe_timeout);
		ks_attr_tear_down_locked(attr);
		ks_attr_put(attr);	/* drop the engaged_list ref */
	} else {
		atomic_set(&attr->state, KS_ENGAGED);
		attr->probe_deadline = 0;
		pr_warn("killswitch: tryengage %s committed: 0 hits in %us\n",
			attr->kp.symbol_name, attr->probe_timeout);
	}

out:
	mutex_unlock(&ks_lock);
	ks_attr_put(attr);	/* drop the timer's ref */
}

static int __ks_disengage(const char *symbol)
{
	struct ks_attr *attr;
	unsigned long hits;
	int ret = 0;

	mutex_lock(&ks_lock);
	attr = ks_attr_lookup(symbol);
	if (!attr) {
		ret = -ENOENT;
		goto out_unlock;
	}

	hits = ks_attr_hits(attr);
	ks_attr_tear_down_locked(attr);

	pr_warn("killswitch: disengage %s hits=%lu uid=%u auid=%u ses=%u comm=%s\n",
		symbol, hits,
		from_kuid(&init_user_ns, current_uid()),
		from_kuid(&init_user_ns, audit_get_loginuid(current)),
		audit_get_sessionid(current),
		current->comm);

	/* unregister_kprobe() already waited out in-flight pre-handlers. */
	ks_attr_put(attr);

out_unlock:
	mutex_unlock(&ks_lock);
	return ret;
}

static void ks_disengage_all_locked(void)
{
	struct ks_attr *attr, *n;

	list_for_each_entry_safe(attr, n, &ks_engaged_list, list) {
		pr_warn("killswitch: disengage %s hits=%lu (disengage_all)\n",
			attr->kp.symbol_name, ks_attr_hits(attr));
		ks_attr_tear_down_locked(attr);
		ks_attr_put(attr);
	}
}

/* ------------------------------------------------------------------ *
 * Module unload: drop engagements on functions in the going module   *
 * ------------------------------------------------------------------ */

static int ks_module_notify(struct notifier_block *nb, unsigned long action,
			    void *data)
{
	struct module *mod = data;
	struct ks_attr *attr, *n;

	if (action != MODULE_STATE_GOING)
		return NOTIFY_DONE;

	mutex_lock(&ks_lock);
	list_for_each_entry_safe(attr, n, &ks_engaged_list, list) {
		if (!attr->kp.addr ||
		    !within_module((unsigned long)attr->kp.addr, mod))
			continue;

		pr_warn("killswitch: %s mitigation lost: module %s unloading; re-engage after reload if still needed\n",
			attr->kp.symbol_name, mod->name);
		ks_attr_tear_down_locked(attr);
		ks_attr_put(attr);
	}
	mutex_unlock(&ks_lock);
	return NOTIFY_DONE;
}

static struct notifier_block ks_module_nb = {
	.notifier_call = ks_module_notify,
};

/* ------------------------------------------------------------------ *
 * Top-level securityfs files: control / engaged / taint              *
 * ------------------------------------------------------------------ */

static int ks_engaged_show(struct seq_file *m, void *v)
{
	struct ks_attr *attr;

	mutex_lock(&ks_lock);
	list_for_each_entry(attr, &ks_engaged_list, list) {
		seq_printf(m, "%s retval=%ld hits=%lu\n",
			   attr->kp.symbol_name,
			   atomic_long_read(&attr->retval),
			   ks_attr_hits(attr));
	}
	mutex_unlock(&ks_lock);
	return 0;
}

static int ks_engaged_open(struct inode *inode, struct file *file)
{
	return single_open(file, ks_engaged_show, NULL);
}

static const struct file_operations ks_engaged_fops = {
	.open		= ks_engaged_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/*
 * Reports whether the running image carries the OOT taint that loading
 * this module set.  We don't add a custom TAINT_KILLSWITCH; the module
 * loader already set TAINT_OOT_MODULE the moment killswitch.ko came in,
 * which is the correct semantics: the running kernel deviates from its
 * source.  Always reads 1 while the module is loaded; provided for
 * symmetry with the in-tree feature's `taint` file.
 */
static ssize_t ks_taint_read(struct file *file, char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char buf[4];
	int len;

	len = scnprintf(buf, sizeof(buf), "%d\n",
			test_taint(TAINT_OOT_MODULE) ? 1 : 0);
	return simple_read_from_buffer(ubuf, count, ppos, buf, len);
}

static const struct file_operations ks_taint_fops = {
	.open	= simple_open,
	.read	= ks_taint_read,
	.llseek	= default_llseek,
};

/*
 * control: parse one of:
 *   engage <symbol> <retval>
 *   tryengage <symbol> <retval> <timeout_seconds>
 *   disengage <symbol>
 *   disengage_all
 */
static ssize_t ks_control_write(struct file *file, const char __user *ubuf,
				size_t count, loff_t *ppos)
{
	char *buf, *cur, *verb, *sym, *retstr, *tstr;
	long retval = 0;
	long timeout = 0;
	bool is_tryengage;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (count == 0 || count > 4096)
		return -EINVAL;

	buf = memdup_user_nul(ubuf, count);
	if (IS_ERR(buf))
		return PTR_ERR(buf);

	cur = strim(buf);
	verb = strsep(&cur, " \t\n");
	if (!verb || !*verb) {
		ret = -EINVAL;
		goto out;
	}

	if (!strcmp(verb, "disengage_all")) {
		mutex_lock(&ks_lock);
		ks_disengage_all_locked();
		mutex_unlock(&ks_lock);
		ret = count;
		goto out;
	}

	if (cur)
		cur = skip_spaces(cur);
	sym = strsep(&cur, " \t\n");
	if (!sym || !*sym) {
		ret = -EINVAL;
		goto out;
	}

	if (!strcmp(verb, "disengage")) {
		ret = __ks_disengage(sym);
		ret = ret ? ret : count;
		goto out;
	}

	if (!strcmp(verb, "engagebpf")) {
		char *bpf_path;
		if (cur)
			cur = skip_spaces(cur);
		bpf_path = strsep(&cur, " \t\n");
		if (!bpf_path || !*bpf_path) {
			ret = -EINVAL;
			goto out;
		}
		ret = __ks_engagebpf(sym, bpf_path);
		ret = ret ? ret : count;
		goto out;
	}

	is_tryengage = !strcmp(verb, "tryengage");
	if (!is_tryengage && strcmp(verb, "engage")) {
		ret = -EINVAL;
		goto out;
	}

	if (cur)
		cur = skip_spaces(cur);
	retstr = strsep(&cur, " \t\n");
	if (!retstr || !*retstr) {
		ret = -EINVAL;
		goto out;
	}
	if (kstrtol(retstr, 0, &retval)) {
		ret = -EINVAL;
		goto out;
	}

	if (is_tryengage) {
		if (cur)
			cur = skip_spaces(cur);
		tstr = strsep(&cur, " \t\n");
		if (!tstr || !*tstr || kstrtol(tstr, 0, &timeout) ||
		    timeout < 0 || timeout > KS_TRY_MAX_SECONDS) {
			ret = -EINVAL;
			goto out;
		}
		ret = __ks_tryengage(sym, retval, (unsigned int)timeout);
	} else {
		ret = killswitch_engage(sym, retval);
	}
	if (!ret)
		ret = count;

out:
	kfree(buf);
	return ret;
}

static const struct file_operations ks_control_fops = {
	.open	= simple_open,
	.write	= ks_control_write,
	.llseek	= noop_llseek,
};

/* ------------------------------------------------------------------ *
 * Module parameter: engage=fn1=<val>,fn2=<val>,...                   *
 * ------------------------------------------------------------------ */

static void ks_apply_modparam(void)
{
	char *param, *cur, *tok;
	long retval;

	if (!engage || !*engage)
		return;

	/* engage is read-only after module load; copy so strsep can mutate. */
	param = kstrdup(engage, GFP_KERNEL);
	if (!param) {
		pr_warn("killswitch: out of memory parsing engage=\n");
		return;
	}

	cur = param;
	while ((tok = strsep(&cur, ",")) != NULL) {
		char *eq, *sym, *retstr;

		if (!*tok)
			continue;
		eq = strchr(tok, '=');
		if (!eq) {
			pr_warn("killswitch: engage= missing '=': %s\n", tok);
			continue;
		}
		*eq++ = '\0';
		sym = tok;
		retstr = eq;

		if (kstrtol(retstr, 0, &retval)) {
			pr_warn("killswitch: engage= bad retval %s=%s\n",
				sym, retstr);
			continue;
		}

		if (__ks_engage(sym, retval, true))
			pr_warn("killswitch: engage= %s failed\n", sym);
	}

	kfree(param);
}

/* ------------------------------------------------------------------ *
 * Init / exit                                                        *
 * ------------------------------------------------------------------ */

static int __init killswitch_init(void)
{
	struct dentry *d;
	int ret;

	ks_root_dir = securityfs_create_dir("killswitch", NULL);
	if (IS_ERR(ks_root_dir))
		return PTR_ERR(ks_root_dir);

	d = securityfs_create_file("control", 0200, ks_root_dir,
				   NULL, &ks_control_fops);
	if (IS_ERR(d))
		goto err;
	d = securityfs_create_file("engaged", 0444, ks_root_dir,
				   NULL, &ks_engaged_fops);
	if (IS_ERR(d))
		goto err;
	d = securityfs_create_file("taint", 0444, ks_root_dir,
				   NULL, &ks_taint_fops);
	if (IS_ERR(d))
		goto err;

	ks_fn_dir = securityfs_create_dir("fn", ks_root_dir);
	if (IS_ERR(ks_fn_dir)) {
		d = ks_fn_dir;
		goto err;
	}

	ret = register_module_notifier(&ks_module_nb);
	if (ret) {
		securityfs_remove(ks_fn_dir);
		d = ERR_PTR(ret);
		goto err;
	}

	ks_apply_modparam();

	pr_info("killswitch: ready (sysfs at /sys/kernel/security/killswitch/)\n");
	return 0;

err:
	securityfs_remove(ks_root_dir);
	ks_root_dir = NULL;
	ks_fn_dir = NULL;
	return PTR_ERR(d);
}

static void __exit killswitch_exit(void)
{
	struct ks_attr *attr, *n;
	LIST_HEAD(dying);

	unregister_module_notifier(&ks_module_nb);

	/*
	 * Splice every engaged entry onto a local list under the lock so
	 * we can run cancel_delayed_work_sync() (which may sleep and which
	 * acquires ks_lock from inside the work callback) without holding
	 * ks_lock ourselves.  Marking each attr !engaged first means any
	 * commit_work blocked on ks_lock will bail when it finally
	 * acquires the lock — there's nothing valid left for it to do.
	 */
	mutex_lock(&ks_lock);
	/*
	 * Flip the unload barrier before draining.  Any concurrent
	 * __ks_install() / __ks_tryengage() that takes the lock after
	 * this point bails with -ENXIO and never references module text.
	 */
	ks_unloading = true;
	list_for_each_entry(attr, &ks_engaged_list, list)
		attr->engaged = false;
	list_splice_init(&ks_engaged_list, &dying);
	mutex_unlock(&ks_lock);

	/*
	 * Sync-cancel every probe timer so no commit_work survives past
	 * module_exit and ends up running with module text already
	 * unmapped.  cancel_delayed_work_sync() returns true if it
	 * canceled before fire (drop the timer's ref), false if it
	 * waited for the callback (which dropped its own ref).
	 */
	list_for_each_entry_safe(attr, n, &dying, list) {
		if (cancel_delayed_work_sync(&attr->commit_work))
			ks_attr_put(attr);
		unregister_kprobe(&attr->kp);
		list_del(&attr->list);
		securityfs_remove(attr->dir);
		pr_warn("killswitch: unloaded with %s engaged; hits=%lu\n",
			attr->kp.symbol_name, ks_attr_hits(attr));
		ks_attr_put(attr);	/* drop the engaged_list ref */
	}

	securityfs_remove(ks_root_dir);
	ks_root_dir = NULL;
	ks_fn_dir = NULL;
	pr_info("killswitch: unloaded\n");
}

module_init(killswitch_init);
module_exit(killswitch_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sasha Levin <sashal@kernel.org>");
MODULE_DESCRIPTION("Per-function short-circuit mitigation primitive (out-of-tree)");
