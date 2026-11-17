/*
 * ldp_guard.c: la defensa "en espacio de usuario" que el enunciado dice que es eludible.
 * Es una biblioteca para LD_PRELOAD que envuelve mmap() y la rechaza cuando el descriptor apunta a un
 * archivo cuya ruta contiene "protegido". Se usa SOLO para demostrar por qué esta clase de defensa no basta.
 *
 *   gcc -shared -fPIC -o ldp_guard.so ldp_guard.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void *mmap(void *addr, size_t len, int prot, int flags, int fd, off_t off)
{
	static void *(*real)(void *, size_t, int, int, int, off_t);
	char link[64], path[PATH_MAX] = "";

	if (!real)
		real = dlsym(RTLD_NEXT, "mmap");
	if (fd >= 0) {
		snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
		ssize_t n = readlink(link, path, sizeof(path) - 1);
		if (n > 0 && strstr(path, "protegido")) {
			errno = EACCES;                       /* "politica" de la biblioteca */
			return MAP_FAILED;
		}
	}
	return real(addr, len, prot, flags, fd, off);
}
