/*
 * mmgctl.c: herramienta de administración (requiere root, CAP_SYS_ADMIN).
 *
 *   mmgctl add <uid> r|w|rw     concede permisos en la ACL
 *   mmgctl del <uid>            revoca
 *   mmgctl load <offset> <txt>  carga texto en la bóveda (se cifra dentro del kernel)
 *   mmgctl stats                imprime los contadores de auditoría
 *   mmgctl verify               verifica el MAC de todas las páginas (devuelve # corruptas)
 *   mmgctl tamper <pagina>      [debug] altera 1 bit del cifrado de la página
 *   mmgctl dumpct <pagina>      [debug] imprime la dirección del kernel y el cifrado en hex
 */
#include "mmg_util.h"

static void usage(void)
{
	fprintf(stderr, "uso: mmgctl add <uid> r|w|rw | del <uid> | load <off> <txt> | stats | verify | tamper <pg> | dumpct <pg>\n");
	exit(2);
}

int main(int argc, char **argv)
{
	int fd = mmg_open(O_RDWR);

	if (argc < 2)
		usage();
	if (!strcmp(argv[1], "add") && argc == 4) {
		struct mmguard_uid_ent e = { .uid = atoi(argv[2]) };

		e.perms = (strchr(argv[3], 'r') ? MMGUARD_PERM_READ : 0) |
			  (strchr(argv[3], 'w') ? MMGUARD_PERM_WRITE | MMGUARD_PERM_READ : 0);
		if (ioctl(fd, MMGUARD_IOC_ADD_UID, &e)) { perror("ADD_UID"); return 1; }
		printf("ACL: uid=%u perms=%u\n", e.uid, e.perms);
	} else if (!strcmp(argv[1], "del") && argc == 3) {
		__u32 uid = atoi(argv[2]);

		if (ioctl(fd, MMGUARD_IOC_DEL_UID, &uid)) { perror("DEL_UID"); return 1; }
		printf("ACL: uid=%u revocado\n", uid);
	} else if (!strcmp(argv[1], "load") && argc == 4) {
		struct mmguard_load ld = { .offset = atoi(argv[2]), .len = strlen(argv[3]),
					   .ptr = (uintptr_t)argv[3] };

		if (ioctl(fd, MMGUARD_IOC_LOAD, &ld)) { perror("LOAD"); return 1; }
		printf("cargados %u bytes en offset %u\n", ld.len, ld.offset);
	} else if (!strcmp(argv[1], "stats")) {
		struct mmguard_stats st;

		if (ioctl(fd, MMGUARD_IOC_STATS, &st)) { perror("STATS"); return 1; }
		printf("mmap_ok=%llu mmap_denied=%llu faults=%llu faults_decrypt=%llu faults_refresh=%llu "
		       "mkwrite=%llu seals=%llu seal_pages=%llu integrity_fail=%llu healed=%llu "
		       "remote_denied=%llu write_denied=%llu probe_mmap=%llu\n",
		       (unsigned long long)st.mmap_ok, (unsigned long long)st.mmap_denied,
		       (unsigned long long)st.faults, (unsigned long long)st.faults_decrypt,
		       (unsigned long long)st.faults_refresh, (unsigned long long)st.page_mkwrite,
		       (unsigned long long)st.seals, (unsigned long long)st.seal_pages,
		       (unsigned long long)st.integrity_fail, (unsigned long long)st.healed,
		       (unsigned long long)st.remote_denied, (unsigned long long)st.write_denied,
		       (unsigned long long)st.probe_mmap);
	} else if (!strcmp(argv[1], "verify")) {
		__u32 bad = 0;

		if (ioctl(fd, MMGUARD_IOC_VERIFY, &bad)) { perror("VERIFY"); return 1; }
		printf("paginas corruptas: %u\n", bad);
		return bad ? 3 : 0;
	} else if (!strcmp(argv[1], "tamper") && argc == 3) {
		__u32 pg = atoi(argv[2]);

		if (ioctl(fd, MMGUARD_IOC_DBG_TAMPER_VAULT, &pg)) { perror("TAMPER"); return 1; }
		printf("cifrado de la pagina %u alterado (simulacion)\n", pg);
	} else if (!strcmp(argv[1], "dumpct") && argc == 3) {
		unsigned char buf[PG];
		struct mmguard_dump d = { .page = atoi(argv[2]), .len = PG, .ptr = (uintptr_t)buf };

		if (ioctl(fd, MMGUARD_IOC_DBG_DUMP_CT, &d)) { perror("DUMP_CT"); return 1; }
		printf("kaddr=0x%llx nonce=%llu\n", (unsigned long long)d.kaddr, (unsigned long long)d.nonce);
		for (unsigned i = 0; i < d.len; i++)
			printf("%02x%s", buf[i], (i % 32 == 31) ? "\n" : "");
	} else {
		usage();
	}
	return 0;
}
