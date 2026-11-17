/*
 * ldp_victim.c: un "atacante" que quiere mapear un archivo.
 *   ldp_victim libc <ruta>   usa mmap() de libc (pasa por LD_PRELOAD)
 *   ldp_victim raw  <ruta>   usa syscall(SYS_mmap, ...) directamente (no pasa por libc)
 * Con -static ni siquiera carga la biblioteca precargada.
 * Imprime los primeros bytes si logró mapear.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int raw = argc > 2 && !strcmp(argv[1], "raw");
	const char *path = argc > 2 ? argv[2] : "/dev/null";
	int fd = open(path, O_RDONLY);
	void *p;

	if (fd < 0) { perror("open"); return 2; }
	if (raw)
		p = (void *)syscall(SYS_mmap, NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	else
		p = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED || ((long)p < 0 && (long)p > -4096)) {
		printf("[BLOQUEADO] %s mmap(%s): %s\n", raw ? "syscall directa" : "libc", path, strerror(errno));
		return 1;
	}
	printf("[ACCEDIO] %s mmap(%s): leyo \"%.30s\"\n", raw ? "syscall directa" : "libc", path, (char *)p);
	return 0;
}
