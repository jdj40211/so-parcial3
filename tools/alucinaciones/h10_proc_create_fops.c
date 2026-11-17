// SPDX-License-Identifier: GPL-2.0
/* Candidato típico (kernels < 5.6): proc_create() con struct file_operations. */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
MODULE_LICENSE("GPL");
static const struct file_operations fops = { .owner = THIS_MODULE };
static int __init m_init(void)
{
	return proc_create("mmguard_x", 0444, NULL, &fops) ? 0 : -ENOMEM;   /* ahora exige struct proc_ops */
}
static void __exit m_exit(void) { remove_proc_entry("mmguard_x", NULL); }
module_init(m_init); module_exit(m_exit);
