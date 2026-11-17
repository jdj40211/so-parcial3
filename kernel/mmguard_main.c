// SPDX-License-Identifier: GPL-2.0
/*
 * mmguard_main.c: registro del dispositivo /dev/mmguard, ACL por UID, ioctl.
 *
 * Por qué un dispositivo de caracteres con mmap y no un hook sobre la tabla de
 * llamadas al sistema: ver docs/INFORME.md, preguntas 4 y 3.3. En resumen, la
 * sys_call_table no se exporta desde 5.7, está en memoria de solo lectura y
 * parchearla exige desactivar protecciones de la CPU (WP en CR0 en x86), cosa que
 * es frágil, insegura con varios núcleos y que ni existe igual en arm64.
 */
#include "mmguard.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Juan David Sierra, Andres Prieto (EAFIT, Sistemas Operativos 2026-2)");
MODULE_DESCRIPTION("mmguard: boveda cifrada con mmap protegido, ACL por UID, auditoria e integridad");
MODULE_VERSION("1.0");

/* --------------------------- parámetros del módulo ---------------------- */
bool mmg_verify_on_fault = true;
module_param_named(verify_on_fault, mmg_verify_on_fault, bool, 0644);
MODULE_PARM_DESC(verify_on_fault, "Recalcula SHA-256 de la pagina en claro en cada fallo (1)");

bool mmg_use_vm_io = true;
module_param_named(use_vm_io, mmg_use_vm_io, bool, 0444);
MODULE_PARM_DESC(use_vm_io, "Marca la VMA con VM_IO para bloquear get_user_pages remoto (1)");

bool mmg_allow_debug;
module_param_named(allow_debug, mmg_allow_debug, bool, 0444);
MODULE_PARM_DESC(allow_debug, "Habilita ioctl de depuracion y ataque simulado (0: apagado)");

char *mmg_watch_path = "";
module_param_named(watch_path, mmg_watch_path, charp, 0444);
MODULE_PARM_DESC(watch_path, "Prefijo de ruta cuyos mmap audita el kprobe sobre security_mmap_file");

/* ------------------------------- ACL por UID ---------------------------- */
static struct {
	spinlock_t lock;
	struct { u32 uid; u32 perms; bool used; } e[MMG_MAX_UIDS];
} acl = { .lock = __SPIN_LOCK_UNLOCKED(acl.lock) };

u32 mmg_policy_lookup(kuid_t kuid)
{
	u32 uid = from_kuid(&init_user_ns, kuid), perms = 0;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&acl.lock, flags);
	for (i = 0; i < MMG_MAX_UIDS; i++)
		if (acl.e[i].used && acl.e[i].uid == uid)
			perms = acl.e[i].perms;
	spin_unlock_irqrestore(&acl.lock, flags);
	return perms;
}

static int policy_set(u32 uid, u32 perms)
{
	unsigned long flags;
	int i, slot = -1, ret = 0;

	if (perms & ~(MMGUARD_PERM_READ | MMGUARD_PERM_WRITE))
		return -EINVAL;
	spin_lock_irqsave(&acl.lock, flags);
	for (i = 0; i < MMG_MAX_UIDS; i++) {
		if (acl.e[i].used && acl.e[i].uid == uid) {
			slot = i;
			break;
		}
		if (!acl.e[i].used && slot < 0)
			slot = i;
	}
	if (slot < 0) {
		ret = -ENOSPC;
	} else if (perms == 0) {          /* quitar */
		acl.e[slot].used = false;
	} else {
		acl.e[slot].used = true;
		acl.e[slot].uid = uid;
		acl.e[slot].perms = perms;
	}
	spin_unlock_irqrestore(&acl.lock, flags);
	return ret;
}

/* ------------------------------ file_operations ------------------------- */

static int mmg_open(struct inode *inode, struct file *filp)
{
	struct mmg_session *s = mmg_session_create(filp);

	if (!s)
		return -ENOMEM;
	filp->private_data = s;
	mmg_log(MMG_EV_OPEN, "open() de /dev/mmguard perms_acl=%u", mmg_policy_lookup(current_euid()));
	return 0;
}

static int mmg_release(struct inode *inode, struct file *filp)
{
	struct mmg_session *s = filp->private_data;

	mmg_log(MMG_EV_CLOSE, "close() de /dev/mmguard");
	/* Las VMAs vivas conservan su propia referencia a la sesión. */
	mmg_session_put(s);
	return 0;
}

static int mmg_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return mmg_do_mmap(filp, vma);
}

/* msync(MS_SYNC) sobre un mapa compartido termina aquí (vfs_fsync_range): sella los cambios. */
static int mmg_fsync(struct file *filp, loff_t start, loff_t end, int datasync)
{
	int ret = mmg_session_seal(filp->private_data);

	return ret < 0 ? ret : 0;
}

static long mmg_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct mmg_session *s = filp->private_data;
	void __user *up = (void __user *)arg;
	int ret = 0;

	switch (cmd) {
	case MMGUARD_IOC_ADD_UID: {
		struct mmguard_uid_ent ent;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&ent, up, sizeof(ent)))
			return -EFAULT;
		ret = policy_set(ent.uid, ent.perms);
		mmg_log(MMG_EV_ADMIN, "ACL: uid=%u perms=%u ret=%d", ent.uid, ent.perms, ret);
		return ret;
	}
	case MMGUARD_IOC_DEL_UID: {
		u32 uid;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&uid, up, sizeof(uid)))
			return -EFAULT;
		ret = policy_set(uid, 0);
		mmg_log(MMG_EV_ADMIN, "ACL: uid=%u revocado ret=%d", uid, ret);
		return ret;
	}
	case MMGUARD_IOC_LOAD: {
		struct mmguard_load ld;
		u8 *buf;

		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (copy_from_user(&ld, up, sizeof(ld)))
			return -EFAULT;
		if (ld.len == 0 || ld.len > MMG_PAGES * PAGE_SIZE)
			return -EINVAL;
		buf = memdup_user(u64_to_user_ptr(ld.ptr), ld.len);   /* antes de tomar locks internos */
		if (IS_ERR(buf))
			return PTR_ERR(buf);
		ret = mmg_vault_load(ld.offset, buf, ld.len);
		memzero_explicit(buf, ld.len);
		kfree(buf);
		mmg_log(MMG_EV_ADMIN, "LOAD offset=%u len=%u ret=%d", ld.offset, ld.len, ret);
		return ret;
	}
	case MMGUARD_IOC_SEAL:
		ret = mmg_session_seal(s);
		return ret < 0 ? ret : 0;
	case MMGUARD_IOC_VERIFY: {
		u32 bad = mmg_vault_verify_all();

		return put_user(bad, (u32 __user *)up);
	}
	case MMGUARD_IOC_STATS: {
		struct mmguard_stats st = {
			.mmap_ok = mmg_counter(MMG_C_MMAP_OK),
			.mmap_denied = mmg_counter(MMG_C_MMAP_DENIED),
			.faults = mmg_counter(MMG_C_FAULT),
			.faults_decrypt = mmg_counter(MMG_C_FAULT_DECRYPT),
			.faults_refresh = mmg_counter(MMG_C_FAULT_REFRESH),
			.page_mkwrite = mmg_counter(MMG_C_MKWRITE),
			.seals = mmg_counter(MMG_C_SEAL),
			.seal_pages = mmg_counter(MMG_C_SEAL_PAGES),
			.integrity_fail = mmg_counter(MMG_C_INTEG_FAIL),
			.healed = mmg_counter(MMG_C_HEALED),
			.remote_denied = mmg_counter(MMG_C_REMOTE_DENIED),
			.write_denied = mmg_counter(MMG_C_WRITE_DENIED),
			.probe_mmap = mmg_counter(MMG_C_PROBE_MMAP),
		};

		return copy_to_user(up, &st, sizeof(st)) ? -EFAULT : 0;
	}
	case MMGUARD_IOC_DBG_TAMPER_VAULT:
	case MMGUARD_IOC_DBG_CORRUPT_PAGE:
	case MMGUARD_IOC_DBG_DUMP_CT: {
		u32 idx;

		if (!mmg_allow_debug)
			return -ENOTTY;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		if (cmd == MMGUARD_IOC_DBG_DUMP_CT) {
			struct mmguard_dump d;

			if (copy_from_user(&d, up, sizeof(d)))
				return -EFAULT;
			ret = mmg_vault_dbg_dump(&d);
			if (!ret && copy_to_user(up, &d, sizeof(d)))
				ret = -EFAULT;
			return ret;
		}
		if (copy_from_user(&idx, up, sizeof(idx)))
			return -EFAULT;
		return cmd == MMGUARD_IOC_DBG_TAMPER_VAULT ? mmg_vault_dbg_tamper(idx)
							   : mmg_session_dbg_corrupt(s, idx);
	}
	default:
		return -ENOTTY;
	}
}

static const struct file_operations mmg_fops = {
	.owner          = THIS_MODULE,
	.open           = mmg_open,
	.release        = mmg_release,
	.mmap           = mmg_mmap,
	.fsync          = mmg_fsync,
	.unlocked_ioctl = mmg_ioctl,
	.llseek         = noop_llseek,
};

static struct miscdevice mmg_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = MMGUARD_DEV_NAME,
	.fops  = &mmg_fops,
	.mode  = 0666,       /* abrir es libre; quien manda es la ACL en mmap/fallo */
};

static int __init mmguard_init(void)
{
	int ret;

	ret = mmg_vault_init();
	if (ret)
		return ret;
	ret = mmg_audit_init();
	if (ret)
		goto err_vault;
	ret = misc_register(&mmg_misc);
	if (ret)
		goto err_audit;
	ret = mmg_kprobe_init();
	if (ret)
		pr_warn("kprobe de auditoria no disponible (%d); el resto sigue funcionando\n", ret);

	pr_info("cargado: /dev/%s, verify_on_fault=%d use_vm_io=%d allow_debug=%d watch_path=\"%s\"\n",
		MMGUARD_DEV_NAME, mmg_verify_on_fault, mmg_use_vm_io, mmg_allow_debug, mmg_watch_path);
	return 0;

err_audit:
	mmg_audit_exit();
err_vault:
	mmg_vault_exit();
	return ret;
}

static void __exit mmguard_exit(void)
{
	mmg_kprobe_exit();
	misc_deregister(&mmg_misc);
	mmg_audit_exit();
	mmg_vault_exit();
	pr_info("descargado\n");
}

module_init(mmguard_init);
module_exit(mmguard_exit);
