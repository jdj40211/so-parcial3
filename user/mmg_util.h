/* mmg_util.h: utilidades comunes de los programas de usuario de mmguard. */
#ifndef MMG_UTIL_H
#define MMG_UTIL_H

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mmguard_uapi.h"

#define PG 4096UL

/* Texto con el que el módulo inicializa la página 0 de la bóveda (ver mmguard_vault.c). */
#define SECRET_PREFIX "TOP-SECRET mmguard:"

static inline int mmg_open(int flags)
{
	int fd = open(MMGUARD_DEV_PATH, flags);

	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", MMGUARD_DEV_PATH, strerror(errno));
		exit(2);
	}
	return fd;
}

static inline int mmg_stats(struct mmguard_stats *st)
{
	int fd = mmg_open(O_RDONLY), r;

	r = ioctl(fd, MMGUARD_IOC_STATS, st);
	close(fd);
	return r;
}

/* Imprime "OK/FALLA" con el formato que lee run_tests.sh. */
#define VERDICT(name, cond, fmt, ...) do {                                         \
	printf("[%s] %s: " fmt "\n", (cond) ? "OK" : "FALLA", name, ##__VA_ARGS__);  \
	fflush(stdout);                                                              \
} while (0)

#endif
