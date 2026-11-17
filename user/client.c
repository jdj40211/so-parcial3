/*
 * client.c: cliente AUTORIZADO de la bóveda mmguard.
 *
 *   client read  [pagina] [bytes] [--private]  lee y muestra texto descifrado
 *   client write <pagina> <texto>              escribe (MAP_SHARED) y sella con msync
 *   client hold  [segundos]                    mapea, toca la página 0 y espera
 *                                              (imprime la dirección del mapa)
 *
 * Si el UID no está en la ACL, el mmap devuelve EACCES y este programa lo dice.
 */
#include "mmg_util.h"

static void *map_or_die(int fd, size_t len, int prot, int flags, off_t off)
{
	void *p = mmap(NULL, len, prot, flags, fd, off);

	if (p == MAP_FAILED) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));
		exit(1);
	}
	return p;
}

int main(int argc, char **argv)
{
	const char *cmd = argc > 1 ? argv[1] : "read";

	if (!strcmp(cmd, "read")) {
		int page = argc > 2 ? atoi(argv[2]) : 0;
		int n = argc > 3 ? atoi(argv[3]) : 80;
		int priv = argc > 4 && !strcmp(argv[4], "--private");
		int fd = mmg_open(O_RDONLY);
		char *p = map_or_die(fd, PG, PROT_READ, priv ? MAP_PRIVATE : MAP_SHARED, (off_t)page * PG);

		printf("%.*s\n", n, p);
		return 0;
	}
	if (!strcmp(cmd, "write") && argc > 3) {
		int page = atoi(argv[2]);
		int fd = mmg_open(O_RDWR);
		char *p = map_or_die(fd, PG, PROT_READ | PROT_WRITE, MAP_SHARED, (off_t)page * PG);

		memset(p, 0, PG);
		strncpy(p, argv[3], PG - 1);
		if (msync(p, PG, MS_SYNC)) {       /* msync(MS_SYNC) -> vfs_fsync_range -> mmg_fsync -> sellado */
			perror("msync");
			return 1;
		}
		printf("escrito y sellado en pagina %d: %s\n", page, argv[3]);
		return 0;
	}
	if (!strcmp(cmd, "hold")) {
		int secs = argc > 2 ? atoi(argv[2]) : 5;
		int fd = mmg_open(O_RDONLY);
		volatile char *p = map_or_die(fd, PG, PROT_READ, MAP_SHARED, 0);

		(void)p[0];                         /* provoca el fallo y el descifrado */
		printf("MAPA %lx %d\n", (unsigned long)p, getpid());
		fflush(stdout);
		sleep(secs);
		return 0;
	}
	fprintf(stderr, "uso: client read [pag] [bytes] [--private] | write <pag> <texto> | hold [s]\n");
	return 2;
}
