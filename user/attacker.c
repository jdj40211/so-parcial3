/*
 * attacker.c: ataques controlados contra la bóveda mmguard. Cada subcomando imprime
 * una línea "[OK] nombre: ..." si la DEFENSA funcionó (o "[FALLA]" si el ataque pasó).
 *
 *   unauth          UID sin permiso intenta mapear
 *   mprotect        subir permisos con mprotect(PROT_WRITE / PROT_EXEC) tras un mapa de lectura
 *   shared-write    MAP_SHARED|PROT_WRITE desde un lector
 *   private-write   MAP_PRIVATE|PROT_WRITE (la "evasión de permisos POSIX" de la pregunta 8)
 *   exec            PROT_EXEC
 *   fork            el hijo no hereda el mapa (VM_DONTCOPY)
 *   mremap          intentar agrandar el mapa (VM_DONTEXPAND)
 *   procmem         escribir/leer el mapa por /proc/self/mem (vector de Dirty COW)
 *   after-revoke S  mapea, espera S s (el admin revoca el UID), refalla -> SIGBUS esperado
 *   integ-session   [root] altera la página en claro de la sesión: se debe detectar y reparar
 *   integ-vault     [root] altera el cifrado en la bóveda: se debe detectar (SIGBUS)
 */
#include "mmg_util.h"

#include <setjmp.h>
#include <signal.h>
#include <sys/wait.h>

static sigjmp_buf jb;
static volatile sig_atomic_t last_sig;

static void on_sig(int sig)
{
	last_sig = sig;
	siglongjmp(jb, 1);
}

static void install_handlers(void)
{
	struct sigaction sa = { .sa_handler = on_sig };

	sigemptyset(&sa.sa_mask);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
}

/* Lee un byte de p; devuelve 0 si pudo, o el número de señal si el acceso falló. */
static int try_read(volatile const char *p, char *out)
{
	last_sig = 0;
	if (sigsetjmp(jb, 1) == 0) {
		*out = *p;
		return 0;
	}
	return last_sig;
}

static void *map_ro(int fd, off_t off, int flags)
{
	return mmap(NULL, PG, PROT_READ, flags, fd, off);
}

static int t_unauth(void)
{
	int fd = mmg_open(O_RDWR);
	void *p = map_ro(fd, 0, MAP_SHARED);
	int e1 = errno, ok1 = (p == MAP_FAILED && e1 == EACCES);
	void *q = map_ro(fd, 0, MAP_PRIVATE);
	int e2 = errno, ok2 = (q == MAP_FAILED && e2 == EACCES);

	VERDICT("unauth", ok1 && ok2, "UID %d: mmap SHARED -> %s, mmap PRIVATE -> %s (esperado EACCES)",
		getuid(), p == MAP_FAILED ? strerror(e1) : "PERMITIDO", q == MAP_FAILED ? strerror(e2) : "PERMITIDO");
	return !(ok1 && ok2);
}

static int t_mprotect(void)
{
	int fd = mmg_open(O_RDWR);
	void *p = map_ro(fd, 0, MAP_SHARED);
	int r1, e1, r2, e2, ok;

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	r1 = mprotect(p, PG, PROT_READ | PROT_WRITE); e1 = errno;
	r2 = mprotect(p, PG, PROT_READ | PROT_EXEC);  e2 = errno;
	ok = (r1 == -1 && e1 == EACCES && r2 == -1 && e2 == EACCES);
	VERDICT("mprotect", ok, "mprotect(+WRITE) -> %s, mprotect(+EXEC) -> %s (esperado EACCES; VM_MAYWRITE/VM_MAYEXEC limpios)",
		r1 ? strerror(e1) : "PERMITIDO", r2 ? strerror(e2) : "PERMITIDO");
	return !ok;
}

static int t_shared_write(void)
{
	int fd = mmg_open(O_RDWR);   /* O_RDWR para que el rechazo lo haga el módulo y no el chequeo genérico del VFS */
	void *p = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	int e = errno, ok = (p == MAP_FAILED && e == EACCES);

	VERDICT("shared-write", ok, "mmap(PROT_WRITE, MAP_SHARED) de un lector -> %s (esperado EACCES)",
		p == MAP_FAILED ? strerror(e) : "PERMITIDO");
	return !ok;
}

static int t_private_write(void)
{
	/* Pregunta 8: con O_RDONLY el kernel SÍ permite PROT_WRITE|MAP_PRIVATE en un archivo normal. */
	int cfd = open("/etc/hostname", O_RDONLY);
	void *c = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, cfd, 0);
	int ce = errno;
	int fd = mmg_open(O_RDONLY);
	void *p = mmap(NULL, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	int e = errno, ok = (p == MAP_FAILED && e == EACCES);

	printf("[INFO] control: /etc/hostname O_RDONLY + PROT_WRITE|MAP_PRIVATE -> %s (Linux lo permite: COW privado)\n",
	       c == MAP_FAILED ? strerror(ce) : "PERMITIDO");
	VERDICT("private-write", ok, "mmguard O_RDONLY + PROT_WRITE|MAP_PRIVATE -> %s (esperado EACCES)",
		p == MAP_FAILED ? strerror(e) : "PERMITIDO");
	return !ok;
}

static int t_exec(void)
{
	int fd = mmg_open(O_RDONLY);
	void *p = mmap(NULL, PG, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	int e = errno, ok = (p == MAP_FAILED && e == EACCES);

	VERDICT("exec", ok, "mmap(PROT_EXEC) -> %s (esperado EACCES)", p == MAP_FAILED ? strerror(e) : "PERMITIDO");
	return !ok;
}

static int t_fork(void)
{
	int fd = mmg_open(O_RDONLY), st;
	volatile char *p = map_ro(fd, 0, MAP_SHARED);
	char c;
	pid_t pid;

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	if (try_read(p, &c)) { puts("el padre no pudo leer"); return 2; }
	pid = fork();
	if (pid == 0) {
		install_handlers();
		_exit(try_read(p, &c) == SIGSEGV ? 77 : 0);   /* 77: el hijo recibió SIGSEGV (no hay mapa) */
	}
	waitpid(pid, &st, 0);
	VERDICT("fork", WIFEXITED(st) && WEXITSTATUS(st) == 77,
		"el hijo accede a la region heredada -> %s (esperado SIGSEGV por VM_DONTCOPY)",
		(WIFEXITED(st) && WEXITSTATUS(st) == 77) ? "SIGSEGV" : "ACCESO PERMITIDO");
	return !(WIFEXITED(st) && WEXITSTATUS(st) == 77);
}

static int t_mremap(void)
{
	int fd = mmg_open(O_RDONLY);
	void *p = map_ro(fd, 0, MAP_SHARED), *q;
	int e, ok;

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	q = mremap(p, PG, 2 * PG, MREMAP_MAYMOVE);
	e = errno;
	ok = (q == MAP_FAILED);
	VERDICT("mremap", ok, "mremap(agrandar x2) -> %s (esperado fallo por VM_DONTEXPAND)",
		q == MAP_FAILED ? strerror(e) : "PERMITIDO");
	return !ok;
}

static int t_procmem(void)
{
	int fd = mmg_open(O_RDONLY);
	char *p = map_ro(fd, 0, MAP_PRIVATE);   /* el Dirty COW clásico apunta a un mapa privado de solo lectura */
	int mfd = open("/proc/self/mem", O_RDWR);
	char evil[] = "HACKEADO!", before[16], after[16], c;
	ssize_t w, r;
	int e1, e2;

	if (p == MAP_FAILED || mfd < 0) { perror("mmap/open"); return 2; }
	install_handlers();
	if (try_read(p, &c)) { puts("lectura inicial fallo"); return 2; }
	memcpy(before, p, 15); before[15] = 0;
	w = pwrite(mfd, evil, sizeof(evil) - 1, (off_t)(uintptr_t)p);
	e1 = errno;
	r = pread(mfd, after, 8, (off_t)(uintptr_t)p);
	e2 = errno;
	memcpy(after, p, 15); after[15] = 0;
	int ok = (w < 0) && !memcmp(before, after, 15);
	VERDICT("procmem", ok, "pwrite(/proc/self/mem) -> %s; pread(/proc/self/mem) -> %s; contenido intacto=%s",
		w < 0 ? strerror(e1) : "ESCRIBIO", r < 0 ? strerror(e2) : "leyo", !memcmp(before, after, 15) ? "si" : "NO");
	return !ok;
}

static int t_after_revoke(int secs)
{
	int fd = mmg_open(O_RDONLY);
	volatile char *p = map_ro(fd, 0, MAP_SHARED);
	char c;
	int s1, s2;

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	install_handlers();
	s1 = try_read(p, &c);
	printf("LISTO\n");
	fflush(stdout);
	sleep(secs);                         /* aquí el administrador revoca el UID en la ACL */
	madvise((void *)p, PG, MADV_DONTNEED);   /* descarta la PTE: el próximo acceso vuelve a fallar */
	s2 = try_read(p, &c);
	VERDICT("revoke", s1 == 0 && s2 == SIGBUS, "antes de revocar: %s; tras revocar y refallar: %s (esperado SIGBUS)",
		s1 ? "ERROR" : "lee", s2 == SIGBUS ? "SIGBUS" : (s2 ? "otra senal" : "SIGUE LEYENDO"));
	return !(s1 == 0 && s2 == SIGBUS);
}

static int t_integ_session(void)
{
	int fd = mmg_open(O_RDWR);
	volatile char *p = map_ro(fd, 0, MAP_SHARED);
	struct mmguard_stats a, b;
	__u32 pg = 0;
	char first[64], again[64];
	int ok;

	if (p == MAP_FAILED) { perror("mmap"); return 2; }
	mmg_stats(&a);
	memcpy(first, (const void *)p, 63); first[63] = 0;
	if (ioctl(fd, MMGUARD_IOC_DBG_CORRUPT_PAGE, &pg)) { perror("CORRUPT_PAGE (allow_debug=1?)"); return 2; }
	/* Simula que un Dirty COW escribió sobre el marco físico: la PTE sigue vigente, así que
	 * el proceso ya vería el byte corrupto; al descartar la PTE el kernel debe detectarlo. */
	printf("[INFO] byte 0 tras la corrupcion simulada: 0x%02x (antes 0x%02x)\n", (unsigned char)p[0], (unsigned char)first[0]);
	madvise((void *)p, PG, MADV_DONTNEED);
	memcpy(again, (const void *)p, 63); again[63] = 0;
	mmg_stats(&b);
	ok = !strcmp(first, again) && b.integrity_fail == a.integrity_fail + 1 && b.healed == a.healed + 1;
	VERDICT("integ-session", ok, "tras refallar: contenido restaurado=%s, violaciones +%llu, reparadas +%llu",
		!strcmp(first, again) ? "si" : "NO", (unsigned long long)(b.integrity_fail - a.integrity_fail),
		(unsigned long long)(b.healed - a.healed));
	return !ok;
}

static int t_integ_vault(void)
{
	int fd = mmg_open(O_RDWR), st;
	struct mmguard_stats a, b;
	__u32 pg = 3, bad = 0;
	pid_t pid;
	char buf[PG];
	struct mmguard_load ld = { .offset = 3 * PG, .len = PG, .ptr = (uintptr_t)buf };

	mmg_stats(&a);
	if (ioctl(fd, MMGUARD_IOC_DBG_TAMPER_VAULT, &pg)) { perror("TAMPER (allow_debug=1?)"); return 2; }
	ioctl(fd, MMGUARD_IOC_VERIFY, &bad);
	pid = fork();
	if (pid == 0) {                       /* sesión nueva: su descifrado de la página 3 debe fallar */
		int cfd = mmg_open(O_RDONLY);
		volatile char *q = mmap(NULL, PG, PROT_READ, MAP_SHARED, cfd, 3 * PG);
		char c;

		install_handlers();
		_exit(q != MAP_FAILED && try_read(q, &c) == SIGBUS ? 77 : 0);
	}
	waitpid(pid, &st, 0);
	mmg_stats(&b);
	/* Reprovisión: reescribir la página completa devuelve la bóveda a un estado sano. */
	memset(buf, 0, PG);
	snprintf(buf, PG, "PAGINA-03: contenido protegido de la boveda, pagina numero 3.\n");
	if (ioctl(fd, MMGUARD_IOC_LOAD, &ld)) perror("LOAD");
	int ok = bad == 1 && WIFEXITED(st) && WEXITSTATUS(st) == 77 && b.integrity_fail > a.integrity_fail;
	VERDICT("integ-vault", ok, "VERIFY reporta %u pagina(s) corrupta(s); lector nuevo -> %s; violaciones +%llu",
		bad, (WIFEXITED(st) && WEXITSTATUS(st) == 77) ? "SIGBUS" : "LEYO DATOS ALTERADOS",
		(unsigned long long)(b.integrity_fail - a.integrity_fail));
	return !ok;
}

int main(int argc, char **argv)
{
	const char *t = argc > 1 ? argv[1] : "";

	if (!strcmp(t, "unauth")) return t_unauth();
	if (!strcmp(t, "mprotect")) return t_mprotect();
	if (!strcmp(t, "shared-write")) return t_shared_write();
	if (!strcmp(t, "private-write")) return t_private_write();
	if (!strcmp(t, "exec")) return t_exec();
	if (!strcmp(t, "fork")) return t_fork();
	if (!strcmp(t, "mremap")) return t_mremap();
	if (!strcmp(t, "procmem")) return t_procmem();
	if (!strcmp(t, "after-revoke")) return t_after_revoke(argc > 2 ? atoi(argv[2]) : 2);
	if (!strcmp(t, "integ-session")) return t_integ_session();
	if (!strcmp(t, "integ-vault")) return t_integ_vault();
	fprintf(stderr, "subcomandos: unauth mprotect shared-write private-write exec fork mremap procmem after-revoke integ-session integ-vault\n");
	return 2;
}
