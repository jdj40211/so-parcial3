// SPDX-License-Identifier: GPL-2.0
/*
 * mmguard_vm.c: la parte "de memoria virtual" del módulo.
 *
 *  - mmg_do_mmap():  validación de permisos y endurecimiento de la VMA.
 *  - mmg_vm_fault(): descifra UNA página bajo demanda, solo para el proceso dueño.
 *  - mmg_vm_page_mkwrite(): notificación de primera escritura (marca la página sucia).
 *  - mmg_session_seal(): re-cifra las páginas sucias (msync, ioctl, cierre).
 *
 * Aislamiento: el texto en claro vive en páginas privadas de la sesión (una
 * por open()), NO en la bóveda ni en una caché de páginas compartida. Dos procesos
 * jamás comparten un marco físico con datos descifrados.
 */
#include "mmguard.h"

#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>

/* ------------------------------------------------------------------ */
/* Ciclo de vida de la sesión                                           */
/* ------------------------------------------------------------------ */

struct mmg_session *mmg_session_create(struct file *filp)
{
	struct mmg_session *s = kzalloc(sizeof(*s), GFP_KERNEL);

	if (!s)
		return NULL;
	kref_init(&s->ref);
	mutex_init(&s->lock);
	INIT_LIST_HEAD(&s->retired);
	s->owner = current_euid();
	s->mapping = filp->f_mapping;   /* address_space de /dev/mmguard: lo usa unmap_mapping_range */
	return s;
}

void mmg_session_get(struct mmg_session *s)
{
	kref_get(&s->ref);
}

/* El texto en claro no debe sobrevivir en RAM libre: se borra antes de devolver la página. */
static void free_plain_page(struct page *pg)
{
	memzero_explicit(page_address(pg), PAGE_SIZE);
	ClearPageDirty(pg);
	__free_page(pg);
}

struct mmg_retired {
	struct list_head node;
	struct page *pg;
};

/* Libera las páginas retiradas que ya nadie tiene mapeadas (page_count == 1: solo la lista). */
static void reap_retired(struct mmg_session *s, bool all)
{
	struct mmg_retired *r, *tmp;

	list_for_each_entry_safe(r, tmp, &s->retired, node) {
		if (all || page_count(r->pg) == 1) {
			free_plain_page(r->pg);
			list_del(&r->node);
			kfree(r);
		}
	}
}

/*
 * Reemplazo "copy-on-refresh": una página en claro que ya pudo ser mapeada NO se reescribe
 * en sitio (un lector con la PTE viva vería una mezcla de dos versiones). Se descifra en una
 * página nueva y la vieja se retira: se libera ya si nadie la tiene mapeada o se deja en
 * s->retired hasta que se desmapee. Requiere s->lock.
 */
static void retire_page(struct mmg_session *s, struct page *old)
{
	struct mmg_retired *r;

	if (page_count(old) == 1) {
		free_plain_page(old);
		return;
	}
	r = kmalloc(sizeof(*r), GFP_KERNEL | __GFP_NOFAIL);
	r->pg = old;
	list_add(&r->node, &s->retired);
}

static void session_release(struct kref *ref)
{
	struct mmg_session *s = container_of(ref, struct mmg_session, ref);
	int i;

	/* Último en salir: si quedaron cambios sin sellar y la sesión podía escribir, se sellan. */
	if (!bitmap_empty(s->dirty, MMG_PAGES))
		mmg_session_seal(s);

	for (i = 0; i < MMG_PAGES; i++)
		if (s->pt[i])
			free_plain_page(s->pt[i]);
	/* Sin VMAs vivas no queda ninguna PTE: todas las páginas retiradas están libres de referencias. */
	reap_retired(s, true);
	kfree(s);
}

void mmg_session_put(struct mmg_session *s)
{
	kref_put(&s->ref, session_release);
}

/* ------------------------------------------------------------------ */
/* Páginas en claro de la sesión                                        */
/* ------------------------------------------------------------------ */

/*
 * (Re)descifra la página idx desde la bóveda hacia una página PRIVADA NUEVA y la publica en
 * s->pt[idx] solo cuando ya está completa. Requiere s->lock.
 */
static int session_decrypt_locked(struct mmg_session *s, unsigned int idx)
{
	struct page *new = alloc_page(GFP_KERNEL | __GFP_ZERO);
	void *dst;
	u64 nonce;
	int ret;

	if (!new)
		return -ENOMEM;
	dst = page_address(new);
	ret = mmg_vault_read_page(idx, dst, &nonce);
	if (!ret)
		ret = mmg_digest(dst, PAGE_SIZE, s->digest[idx]);
	if (ret) {
		free_plain_page(new);
		return ret;
	}
	if (s->pt[idx])
		retire_page(s, s->pt[idx]);
	s->pt[idx] = new;
	s->seen_nonce[idx] = nonce;
	reap_retired(s, false);
	return 0;
}

/*
 * Prepara la página idx para ser mapeada: la crea y descifra si no existe,
 * la refresca (en una página nueva) si la bóveda tiene una versión más nueva, y
 * verifica que nadie la haya alterado desde que se descifró. Requiere s->lock.
 */
static vm_fault_t session_prepare_page(struct mmg_session *s, unsigned int idx)
{
	bool dirty = test_bit(idx, s->dirty);
	int ret;

	if (!s->pt[idx]) {
		ret = session_decrypt_locked(s, idx);
		if (ret == -ENOMEM)
			return VM_FAULT_OOM;
		if (ret) {
			mmg_log(MMG_EV_INTEGRITY, "pagina=%u no se pudo descifrar/autenticar (err=%d) -> SIGBUS",
				idx, ret);
			return VM_FAULT_SIGBUS;
		}
		mmg_count(MMG_C_FAULT_DECRYPT);
		return 0;
	}

	if (dirty)              /* cambios legítimos aún sin sellar: no se tocan */
		return 0;

	/* ¿Otra sesión selló una versión más nueva? Entonces esta copia está obsoleta. */
	if (mmg_vault_nonce(idx) != s->seen_nonce[idx]) {
		ret = session_decrypt_locked(s, idx);
		if (ret) {
			mmg_log(MMG_EV_INTEGRITY, "pagina=%u refresco fallido (err=%d) -> SIGBUS", idx, ret);
			return VM_FAULT_SIGBUS;
		}
		mmg_count(MMG_C_FAULT_REFRESH);
		return 0;
	}

	/*
	 * Integridad del texto en claro: nadie, salvo page_mkwrite, debería haber
	 * modificado esta página. Si el SHA-256 ya no coincide, algo escribió sobre el
	 * marco físico por una vía no autorizada (p. ej. un Dirty COW). Se audita y
	 * se REPARA volviendo a descifrar desde la bóveda.
	 */
	if (mmg_verify_on_fault) {
		u8 now[MMG_DIGEST_LEN];

		ret = mmg_digest(page_address(s->pt[idx]), PAGE_SIZE, now);
		if (ret)
			return VM_FAULT_SIGBUS;
		if (memcmp(now, s->digest[idx], MMG_DIGEST_LEN)) {
			mmg_count(MMG_C_INTEG_FAIL);
			mmg_log(MMG_EV_INTEGRITY,
				"pagina=%u MODIFICADA sin autorizacion en memoria (SHA-256 no coincide)", idx);
			ret = session_decrypt_locked(s, idx);
			if (ret)
				return VM_FAULT_SIGBUS;
			mmg_count(MMG_C_HEALED);
			mmg_log(MMG_EV_INTEGRITY, "pagina=%u reparada desde la boveda cifrada", idx);
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* vm_operations_struct                                                 */
/* ------------------------------------------------------------------ */

static void mmg_vm_open(struct vm_area_struct *vma)
{
	struct mmg_session *s = vma->vm_private_data;

	/* Se invoca al dividir una VMA (munmap parcial, mprotect parcial). */
	mmg_session_get(s);
	mutex_lock(&s->lock);
	s->nvmas++;
	mutex_unlock(&s->lock);
}

static void mmg_vm_close(struct vm_area_struct *vma)
{
	struct mmg_session *s = vma->vm_private_data;
	bool last;

	mutex_lock(&s->lock);
	last = (--s->nvmas == 0);
	mutex_unlock(&s->lock);

	/* Al desmapear la última VMA se sellan los cambios pendientes (equivale a un msync final). */
	if (last && !bitmap_empty(s->dirty, MMG_PAGES))
		mmg_session_seal(s);
	mmg_session_put(s);
}

/* Se ejecuta en cada fallo de página de la región (PTE ausente). */
static vm_fault_t mmg_vm_fault(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mmg_session *s = vma->vm_private_data;
	unsigned int idx = vmf->pgoff;
	vm_fault_t ret;

	mmg_count(MMG_C_FAULT);

	if (idx >= MMG_PAGES)
		return VM_FAULT_SIGBUS;

	/*
	 * Solo el proceso dueño del mapa puede provocar el descifrado. Un fallo "remoto"
	 * (get_user_pages desde ptrace, /proc/<pid>/mem, process_vm_readv) corre con
	 * current->mm distinto de vma->vm_mm: se rechaza y se audita.
	 */
	if (current->mm != vma->vm_mm) {
		mmg_count(MMG_C_REMOTE_DENIED);
		mmg_log(MMG_EV_DENY, "acceso REMOTO a pagina=%u rechazado (mm ajeno)", idx);
		return VM_FAULT_SIGBUS;
	}
	if (!uid_eq(current_euid(), s->owner)) {
		mmg_count(MMG_C_REMOTE_DENIED);
		mmg_log(MMG_EV_DENY, "fallo de pagina=%u con euid distinto al del open() -> SIGBUS", idx);
		return VM_FAULT_SIGBUS;
	}

	/* La ACL se consulta en vivo: revocar un UID surte efecto en el siguiente fallo. */
	if (!(mmg_policy_lookup(current_euid()) & MMGUARD_PERM_READ)) {
		mmg_count(MMG_C_REMOTE_DENIED);
		mmg_log(MMG_EV_DENY, "fallo de pagina=%u: UID revocado en la ACL -> SIGBUS", idx);
		return VM_FAULT_SIGBUS;
	}

	mutex_lock(&s->lock);
	ret = session_prepare_page(s, idx);
	if (!ret) {
		get_page(s->pt[idx]);       /* la referencia la suelta el kernel al desmapear la PTE */
		vmf->page = s->pt[idx];
	}
	mutex_unlock(&s->lock);

	if (!ret)
		mmg_log(MMG_EV_FAULT, "pagina=%u va=0x%lx %s", idx, vmf->address,
			(vmf->flags & FAULT_FLAG_WRITE) ? "escritura" : "lectura");
	return ret;
}

/*
 * Primera escritura sobre una página mapeada de forma compartida y escribible.
 * Como la VMA tiene page_mkwrite, el kernel mantiene la PTE de solo lectura
 * hasta que este callback autoriza la escritura. Aquí se marca la página como
 * sucia (se sellará con msync/cierre) y se audita.
 */
static vm_fault_t mmg_vm_page_mkwrite(struct vm_fault *vmf)
{
	struct vm_area_struct *vma = vmf->vma;
	struct mmg_session *s = vma->vm_private_data;
	unsigned int idx = vmf->pgoff;

	if (idx >= MMG_PAGES || !(mmg_policy_lookup(current_euid()) & MMGUARD_PERM_WRITE) ||
	    !(vma->vm_flags & VM_WRITE) || current->mm != vma->vm_mm) {
		mmg_count(MMG_C_WRITE_DENIED);
		mmg_log(MMG_EV_DENY, "escritura no autorizada en pagina=%u -> SIGBUS", idx);
		return VM_FAULT_SIGBUS;
	}

	mutex_lock(&s->lock);
	if (vmf->page != s->pt[idx]) {
		/* La PTE apunta a una versión retirada (otra VMA de la sesión provocó un refresco):
		 * se descarta esa PTE y se reintenta el fallo, que ya verá la página vigente. */
		mutex_unlock(&s->lock);
		unmap_mapping_range(s->mapping, (loff_t)idx << PAGE_SHIFT, PAGE_SIZE, 1);
		return VM_FAULT_NOPAGE;
	}
	set_bit(idx, s->dirty);
	mutex_unlock(&s->lock);

	mmg_count(MMG_C_MKWRITE);
	mmg_log(MMG_EV_MKWRITE, "pagina=%u marcada sucia (pendiente de sellar)", idx);

	/* do_page_mkwrite() espera la página bloqueada si devolvemos VM_FAULT_LOCKED. */
	lock_page(vmf->page);
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct mmg_vm_ops = {
	.open         = mmg_vm_open,
	.close        = mmg_vm_close,
	.fault        = mmg_vm_fault,
	.page_mkwrite = mmg_vm_page_mkwrite,
	/* Sin .access: ptrace/process_vm_readv/ /proc/pid/mem no pueden leer ni escribir la región. */
};

/* ------------------------------------------------------------------ */
/* Sellado: re-cifrar lo que el escritor modificó                       */
/* ------------------------------------------------------------------ */

int mmg_session_seal(struct mmg_session *s)
{
	DECLARE_BITMAP(mask, MMG_PAGES);
	struct page *snap;
	unsigned long b;
	int sealed = 0, ret = 0;

	if (!(s->perms & MMGUARD_PERM_WRITE))
		return 0;

	/* 1) Qué páginas están sucias ahora. */
	mutex_lock(&s->lock);
	bitmap_copy(mask, s->dirty, MMG_PAGES);
	mutex_unlock(&s->lock);
	if (bitmap_empty(mask, MMG_PAGES)) {
		mmg_log(MMG_EV_SEAL, "sellado: nada pendiente");
		return 0;
	}

	snap = alloc_page(GFP_KERNEL);
	if (!snap)
		return -ENOMEM;

	/*
	 * 2) Quitar las PTE de ESAS páginas en todos los procesos (rango pgoff = índice de bóveda).
	 *    Desde aquí cualquier escritura nueva falla en page_mkwrite y se bloquea en s->lock
	 *    hasta que terminemos, y cualquier lector refalla y verá la versión nueva.
	 */
	for_each_set_bit(b, mask, MMG_PAGES)
		unmap_mapping_range(s->mapping, (loff_t)b << PAGE_SHIFT, PAGE_SIZE, 1);

	/* 3) Copiar y cifrar bajo el mutex. Solo se sellan páginas que seguían sucias: las que
	 *    se ensuciaron después de la copia de la máscara se tratan en el siguiente sellado. */
	mutex_lock(&s->lock);
	for_each_set_bit(b, mask, MMG_PAGES) {
		if (!test_bit(b, s->dirty))
			continue;
		memcpy(page_address(snap), page_address(s->pt[b]), PAGE_SIZE);
		ret = mmg_vault_write_page(b, page_address(snap));
		if (ret)
			break;
		ret = mmg_digest(page_address(snap), PAGE_SIZE, s->digest[b]);
		if (ret)
			break;
		s->seen_nonce[b] = mmg_vault_nonce(b);
		clear_bit(b, s->dirty);
		sealed++;
	}
	mutex_unlock(&s->lock);

	free_plain_page(snap);

	if (sealed) {
		mmg_count(MMG_C_SEAL);
		for (b = 0; b < (unsigned long)sealed; b++)
			mmg_count(MMG_C_SEAL_PAGES);
	}
	mmg_log(MMG_EV_SEAL, "sellado: %d pagina(s) re-cifradas (ret=%d)", sealed, ret);
	return ret ? ret : sealed;
}

int mmg_session_dbg_corrupt(struct mmg_session *s, unsigned int idx)
{
	u8 *p;

	if (idx >= MMG_PAGES)
		return -EINVAL;
	mutex_lock(&s->lock);
	if (!s->pt[idx]) {
		mutex_unlock(&s->lock);
		return -ENOENT;
	}
	p = page_address(s->pt[idx]);
	p[0] ^= 0xff;         /* simula un Dirty COW: el marco físico cambia sin pasar por page_mkwrite */
	mutex_unlock(&s->lock);
	mmg_log(MMG_EV_ADMIN, "MODO DEPURACION: corrompe 1 byte de la pagina en claro %u de la sesion", idx);
	return 0;
}

/* ------------------------------------------------------------------ */
/* mmap(): validación de permisos y endurecimiento de la VMA            */
/* ------------------------------------------------------------------ */

static int mmg_deny(const char *why, int err, struct vm_area_struct *vma)
{
	mmg_count(MMG_C_MMAP_DENIED);
	mmg_log(MMG_EV_DENY, "mmap rechazado (%s) prot=%c%c%c %s len=%lu off=%lu err=%d", why,
		(vma->vm_flags & VM_READ) ? 'r' : '-', (vma->vm_flags & VM_WRITE) ? 'w' : '-',
		(vma->vm_flags & VM_EXEC) ? 'x' : '-', (vma->vm_flags & VM_SHARED) ? "SHARED" : "PRIVATE",
		vma->vm_end - vma->vm_start, vma->vm_pgoff << PAGE_SHIFT, -err);
	return err;
}

int mmg_do_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct mmg_session *s = filp->private_data;
	unsigned long npages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
	u32 perms = mmg_policy_lookup(current_euid());
	vm_flags_t add = VM_DONTCOPY | VM_DONTEXPAND | VM_DONTDUMP;

	/* 1) El fd solo sirve al UID que hizo open() (evita pasar el fd a otro usuario por SCM_RIGHTS). */
	if (!uid_eq(current_euid(), s->owner))
		return mmg_deny("euid distinto del que abrio el fd", -EACCES, vma);

	/* 2) ACL: el UID debe tener al menos lectura. */
	if (!(perms & MMGUARD_PERM_READ))
		return mmg_deny("uid no autorizado", -EACCES, vma);

	/* 3) Rango dentro de la bóveda. */
	if (vma->vm_pgoff >= MMG_PAGES || npages > MMG_PAGES - vma->vm_pgoff)
		return mmg_deny("rango fuera de la boveda", -EINVAL, vma);

	/* 4) Nunca ejecutable (refuerza NX: ni PROT_EXEC ahora ni mprotect(PROT_EXEC) después). */
	if (vma->vm_flags & VM_EXEC)
		return mmg_deny("PROT_EXEC prohibido", -EACCES, vma);

	/* 5) Escritura: solo con permiso de escritura en la ACL y solo MAP_SHARED. */
	if (vma->vm_flags & VM_WRITE) {
		if (!(perms & MMGUARD_PERM_WRITE)) {
			mmg_count(MMG_C_WRITE_DENIED);
			return mmg_deny("PROT_WRITE sin permiso de escritura", -EACCES, vma);
		}
		if (!(vma->vm_flags & VM_SHARED))
			/* Un COW privado crearía copias anónimas en claro que nadie sellaría ni auditaría. */
			return mmg_deny("PROT_WRITE con MAP_PRIVATE no soportado", -EINVAL, vma);
	}

	/*
	 * Banderas de la VMA (cada una con su razón):
	 *  VM_DONTCOPY   : fork() no hereda el mapa; un hijo no obtiene texto en claro "gratis".
	 *  VM_DONTEXPAND : mremap() no puede agrandar la región más allá de la bóveda.
	 *  VM_DONTDUMP   : el texto en claro no entra en los core dumps.
	 *  VM_IO         : get_user_pages() rechaza la VMA, o sea ptrace, /proc/pid/mem y
	 *                  process_vm_readv no pueden leer ni escribir (incluye FOLL_FORCE).
	 *  VM_MAYEXEC    : se limpia siempre; mprotect(PROT_EXEC) falla con EACCES.
	 *  VM_MAYWRITE   : se limpia si el mapa no nació escribible; así mprotect(PROT_WRITE)
	 *                  falla con EACCES y, además, el mapa deja de ser "COW mapping"
	 *                  (is_cow_mapping() exige VM_MAYWRITE), cerrando el camino de Dirty COW.
	 */
	if (mmg_use_vm_io)
		add |= VM_IO;
	vm_flags_set(vma, add);
	vm_flags_clear(vma, VM_MAYEXEC);
	if (!(vma->vm_flags & VM_WRITE))
		vm_flags_clear(vma, VM_MAYWRITE);

	vma->vm_ops = &mmg_vm_ops;
	vma->vm_private_data = s;
	mmg_session_get(s);          /* referencia de la VMA; se suelta en mmg_vm_close */

	mutex_lock(&s->lock);
	s->perms = perms;
	s->nvmas++;
	if (vma->vm_flags & VM_WRITE)
		s->writer_vma = true;
	mutex_unlock(&s->lock);

	mmg_count(MMG_C_MMAP_OK);
	mmg_log(MMG_EV_MMAP, "mmap autorizado perms=%c%c %s len=%lu off=%lu flags_vma=0x%lx",
		(perms & MMGUARD_PERM_READ) ? 'r' : '-', (perms & MMGUARD_PERM_WRITE) ? 'w' : '-',
		(vma->vm_flags & VM_SHARED) ? "SHARED" : "PRIVATE", npages << PAGE_SHIFT,
		vma->vm_pgoff << PAGE_SHIFT, (unsigned long)vma->vm_flags);
	return 0;
}
