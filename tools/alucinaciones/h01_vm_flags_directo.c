// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 6.3): modificar vm_flags con |= dentro de mmap(). */
#include <linux/module.h>
#include <linux/mm.h>
MODULE_LICENSE("GPL");
static int cand_mmap(struct file *f, struct vm_area_struct *vma)
{
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;   /* en 6.8: vm_flags es const */
	return 0;
}
static const struct file_operations fops = { .mmap = cand_mmap };
static int __init m_init(void) { return fops.mmap ? 0 : -1; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
