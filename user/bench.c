/*
 * bench.c: microbenchmarks para la sección 4.2 (sobrecosto de mmap y de fallos de página).
 *
 *   bench read   <archivo> N            pread() de 64 KiB (sin mmap)
 *   bench mmap   file <archivo> N       solo mmap()+munmap() de 16 páginas
 *   bench mmap   dev N                  idem sobre /dev/mmguard
 *   bench cold   file <archivo> N       mmap + tocar 16 páginas + munmap (+ open/close para dev)
 *   bench cold   dev N                  sesión nueva por iteración: descifra 16 páginas
 *   bench warm   file <archivo> N       mapa fijo; MADV_DONTNEED + tocar 16 páginas (refallo)
 *   bench warm   dev N                  idem; las páginas en claro ya existen en la sesión
 *
 * Salida: una línea "RESULT modo=... ns_por_iter=... fallos_por_iter=..." fácil de tabular.
 */
#include "mmg_util.h"

#include <sys/resource.h>
#include <time.h>

#define NP 16UL

static double now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e9 + ts.tv_nsec;
}

static long minflt(void)
{
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ru.ru_minflt + ru.ru_majflt;
}

static volatile char sink;

static void touch_all(volatile char *p)
{
	for (unsigned long i = 0; i < NP; i++)
		sink = p[i * PG];
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "";
	int is_dev = argc > 2 && !strcmp(argv[2], "dev");
	const char *path = (!strcmp(mode, "read")) ? argv[2] : (is_dev ? NULL : argv[3]);
	long n = atol(!strcmp(mode, "read") ? argv[3] : (is_dev ? argv[3] : argv[4]));
	char label[64], *buf = NULL;
	double t0, t1;
	long f0, f1;
	int fd = -1;
	volatile char *p = NULL;

	snprintf(label, sizeof(label), "%s-%s", mode, !strcmp(mode, "read") ? "archivo" : (is_dev ? "mmguard" : "archivo"));
	if (!strcmp(mode, "read")) {
		fd = open(path, O_RDONLY);
		buf = malloc(NP * PG);
		if (pread(fd, buf, NP * PG, 0) < 0)           /* calienta */
			return 1;
		t0 = now_ns(); f0 = minflt();
		for (long i = 0; i < n; i++)
			if (pread(fd, buf, NP * PG, 0) < 0)
				return 1;
		goto report;
	}
	if (!is_dev)
		fd = open(path, O_RDONLY);
	else if (strcmp(mode, "cold"))
		fd = mmg_open(O_RDONLY);                       /* mmap y warm reutilizan el fd */
	if (!strcmp(mode, "mmap")) {
		t0 = now_ns(); f0 = minflt();
		for (long i = 0; i < n; i++) {
			void *q = mmap(NULL, NP * PG, PROT_READ, MAP_SHARED, fd, 0);

			if (q == MAP_FAILED) { perror("mmap"); return 1; }
			munmap(q, NP * PG);
		}
	} else if (!strcmp(mode, "cold")) {
		t0 = now_ns(); f0 = minflt();
		for (long i = 0; i < n; i++) {
			int f = is_dev ? mmg_open(O_RDONLY) : fd;
			void *q = mmap(NULL, NP * PG, PROT_READ, MAP_SHARED, f, 0);

			if (q == MAP_FAILED) { perror("mmap"); return 1; }
			touch_all(q);
			munmap(q, NP * PG);
			if (is_dev)
				close(f);
		}
	} else if (!strcmp(mode, "warm")) {
		p = mmap(NULL, NP * PG, PROT_READ, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED) { perror("mmap"); return 1; }
		touch_all(p);
		t0 = now_ns(); f0 = minflt();
		for (long i = 0; i < n; i++) {
			madvise((void *)p, NP * PG, MADV_DONTNEED);
			touch_all(p);
		}
	} else {
		fprintf(stderr, "modos: read mmap cold warm\n");
		return 2;
	}
report:
	t1 = now_ns(); f1 = minflt();
	printf("RESULT modo=%s iteraciones=%ld ns_por_iter=%.0f fallos_por_iter=%.2f\n", label, n,
	       (t1 - t0) / n, (double)(f1 - f0) / n);
	return 0;
}
