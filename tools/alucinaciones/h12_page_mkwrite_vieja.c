// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 4.11): page_mkwrite(vma, vmf) con int. */
#include <linux/module.h>
#include <linux/mm.h>
MODULE_LICENSE("GPL");
static int cand_mkwrite(struct vm_area_struct *vma, struct vm_fault *vmf) { return 0; }
static const struct vm_operations_struct ops = { .page_mkwrite = cand_mkwrite };
static int __init m_init(void) { return ops.page_mkwrite ? 0 : -1; }
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
