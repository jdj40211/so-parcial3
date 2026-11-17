/*
 * stress.c: concurrencia entre un escritor que sella y lectores que refallan.
 *
 *   stress writer <s>   (UID con permiso rw)  reescribe la página 7 con un byte distinto en cada ronda
 *                       y hace msync(MS_SYNC) (sellado).
 *   stress reader <s>   (cualquier UID con r)  descarta su PTE (MADV_DONTNEED) y relee la página 7.
 *
 *   stress check <v>    sesión nueva: la página 7 debe ser uniforme y valer v (la última del escritor).
 *
 * Invariantes: (1) ningún proceso se cuelga (sin interbloqueos); (2) al terminar, una sesión nueva
 * ve exactamente la última versión sellada, completa y uniforme; (3) integrity_fail == 0.
 * Nota: dos accesos del lector a la misma página pueden caer en DOS fallos distintos (el sellado del
 * escritor descarta las PTE) y ver dos versiones selladas distintas; es la semántica normal de mmap
 * sin aislamiento de instantáneas, no una lectura rota. Se informa como dato.
 */
#include "mmg_util.h"

#include <time.h>

int main(int argc, char **argv)
{
	if (argc > 2 && !strcmp(argv[1], "check")) {
		int fd = mmg_open(O_RDONLY);
		volatile unsigned char *q = mmap(NULL, PG, PROT_READ, MAP_SHARED, fd, 7 * PG);
		unsigned want = atoi(argv[2]) & 0xff, bad = 0;

		if (q == MAP_FAILED) { perror("mmap"); return 2; }
		for (unsigned i = 0; i < PG; i++)
			bad += q[i] != want;
		VERDICT("stress-final", bad == 0, "sesion nueva: %u bytes de 4096 distintos de la ultima version sellada (0x%02x)",
			bad, want);
		return bad != 0;
	}
	int writer = argc > 1 && !strcmp(argv[1], "writer");
	int secs = argc > 2 ? atoi(argv[2]) : 3;
	int fd = mmg_open(writer ? O_RDWR : O_RDONLY);
	volatile unsigned char *p = mmap(NULL, PG, writer ? PROT_READ | PROT_WRITE : PROT_READ, MAP_SHARED, fd, 7 * PG);
	unsigned long rounds = 0, torn = 0, changes = 0;
	unsigned char last = 0, v = 0;
	time_t t0 = time(NULL);

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	while (time(NULL) - t0 < secs) {
		if (writer) {
			v++;
			memset((void *)p, v, PG);
			if (msync((void *)p, PG, MS_SYNC)) { perror("msync"); return 2; }
		} else {
			unsigned char a, b;

			madvise((void *)p, PG, MADV_DONTNEED);
			a = p[0]; b = p[PG - 1];
			if (a != b) torn++;
			if (a != last) { changes++; last = a; }
		}
		rounds++;
	}
	if (writer) {
		VERDICT("stress-escritor", 1, "%lu rondas de escribir+msync terminadas sin errores", rounds);
		printf("FINAL %u\n", v);
	} else {
		VERDICT("stress-lector", 1, "%lu rondas de DONTNEED+leer sin senales ni bloqueos", rounds);
		printf("[INFO] versiones distintas observadas por el lector: %lu; pares (primer,ultimo byte) con 2 versiones por 2 fallos: %lu\n",
		       changes, torn);
	}
	return 0;
}
