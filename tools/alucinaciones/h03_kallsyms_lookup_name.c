// SPDX-License-Identifier: GPL-2.0
/* Candidato típico: ubicar sys_call_table con kallsyms_lookup_name() para parchearla. */
#include <linux/module.h>
#include <linux/kallsyms.h>
MODULE_LICENSE("GPL");
static unsigned long *tabla;
static int __init m_init(void)
{
	tabla = (unsigned long *)kallsyms_lookup_name("sys_call_table");   /* no exportada desde 5.7 */
	return tabla ? 0 : -ENOENT;
}
static void __exit m_exit(void) {}
module_init(m_init); module_exit(m_exit);
