// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 4.11): .fault(struct vm_area_struct *, struct vm_fault *) devolviendo int. */
#include <linux/module.h>
#include <linux/mm.h>
MODULE_LICENSE("GPL");
static int cand_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}
static const struct vm_operations_struct ops = { .fault = cand_fault };
static int __init m_init(void) { return ops.fault ? 0 : -1; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
