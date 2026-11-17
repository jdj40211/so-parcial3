# mmguard: bóveda cifrada con `mmap()` protegido desde el kernel

Parcial 3 de Sistemas Operativos (EAFIT, 2026-2): *Seguridad de archivos mediante intervención en la capa del kernel y mapeo de memoria (`mmap`)*.
Integrantes: Juan David Sierra (GitHub `jdj40211`) y Andrés Prieto.

`mmguard` es un **módulo de kernel Linux (LKM)** que expone `/dev/mmguard`, una "bóveda" de 16 páginas (64 KiB) que
los procesos autorizados leen (y, si tienen permiso, escriben) con `mmap()`, con estas garantías:

| Garantía | Cómo se logra |
|---|---|
| Los datos en la memoria del kernel están **cifrados** | AES-256-CTR (API `crypto_skcipher`) + HMAC-SHA256 (cifrar y luego autenticar) |
| El texto en claro existe solo para quien está autorizado | Descifrado página por página en `vm_operations_struct.fault`, en páginas **privadas por sesión** |
| Control de acceso | ACL por UID revisada en `mmap()` **y en cada fallo de página** (revocación inmediata) |
| Nadie sube permisos después | `VM_MAYWRITE`/`VM_MAYEXEC` limpios, `PROT_EXEC` prohibido, `MAP_PRIVATE`+`PROT_WRITE` prohibido |
| Resistencia a Dirty COW y a lecturas "desde fuera" | `VM_MAYWRITE` limpio (no es *COW mapping*) y `VM_IO` (GUP/ptrace/`/proc/pid/mem` rechazan la VMA) |
| Escritura controlada | `page_mkwrite` marca páginas sucias; `msync(MS_SYNC)`/`close`/`ioctl` las **re-cifran** (sellado) |
| Detección de modificaciones indebidas | MAC en la bóveda + SHA-256 de cada página en claro verificado en cada fallo; auto-reparación |
| Auditoría | `dmesg` (PID, UID, comando) + anillo y contadores en `/proc/mmguard` + `kprobe` opcional sobre `security_mmap_file` |

Probado en **Ubuntu 24.04 aarch64, kernel `6.8.0-147-generic`** (VM Lima `sokernel`). El código usa solo API de 6.x
(`vm_flags_set/clear`, `vm_fault_t`, `proc_create_single`, `crypto_skcipher`); se evitó todo lo que cambió o desapareció entre 5.x y 6.x
(ver `tools/alucinaciones/`). Para compilarlo en 5.x habría que adaptar `vm_flags_set/clear` (en 5.x se asigna `vma->vm_flags` directamente).

## Arquitectura

```
   proceso de usuario (UID autorizado)                    espacio de usuario  (Ring 3)
   ┌─────────────────────────────────┐
   │ fd = open("/dev/mmguard")       │
   │ p  = mmap(fd, PROT_READ, ...)   │ ─────────┐
   │ x  = p[0]   <-- fallo de página │          │
   └─────────────────────────────────┘          │
 ═══════════════════════════════════════════════│═══════════════════════════  frontera Ring 3 / Ring 0
                                                ▼
   ┌──────────────────────── módulo mmguard (Ring 0) ─────────────────────────────────────────┐
   │ mmguard_main.c   file_operations: open / mmap / fsync / ioctl, ACL por UID, /dev/mmguard │
   │      │ mmap()                                                                            │
   │      ▼                                                                                   │
   │ mmguard_vm.c   mmg_do_mmap():  ACL → rangos → ¬EXEC → WRITE solo MAP_SHARED+rw           │
   │                 vm_flags: DONTCOPY|DONTEXPAND|DONTDUMP|IO, ¬MAYEXEC, ¬MAYWRITE           │
   │                vm_ops.fault ─────► ¿mm ajeno? ¿UID revocado? ──► SIGBUS + auditoría      │
   │                      │             página en claro privada de la SESIÓN                  │
   │                      │             (crea/refresca/verifica SHA-256; repara si cambió)    │
   │                vm_ops.page_mkwrite ► marca sucia   │  msync/close/ioctl ► sellado        │
   │                      ▼                                          ▼                        │
   │ mmguard_vault.c  BÓVEDA: 16 páginas CIFRADAS (AES-256-CTR) + HMAC-SHA256 + nonce único   │
   │                  (claves aleatorias solo en memoria del kernel)                          │
   │ mmguard_audit.c  dmesg + anillo + contadores  →  /proc/mmguard                           │
   │ mmguard_kprobe.c kprobe (solo observa) sobre security_mmap_file                          │
   └──────────────────────────────────────────────────────────────────────────────────────────┘
```

## Estructura del repositorio

```
include/mmguard_uapi.h      estructuras e ioctl compartidos módulo <-> usuario
kernel/                     el módulo (mmguard_main.c, _vm.c, _vault.c, _audit.c, _kprobe.c, mmguard.h, Makefile)
user/                       client (cliente autorizado), attacker (ataques), racer (carrera Dirty COW),
                            stress (concurrencia), mmgctl (admin), bench (mediciones),
                            ldp_guard.c + ldp_victim.c (demostración: LD_PRELOAD se elude, el kernel no)
tests/run_tests.sh          TODAS las pruebas, termina con PASA/FALLA
tests/kcore_check.py        demuestra que el contenido en la memoria del kernel está cifrado (/proc/kcore)
tests/remote_read_check.py  root no puede leer el texto en claro desde fuera (/proc/pid/mem, process_vm_readv)
tests/detector_ebpf.sh      bpftrace detecta la firma de Dirty COW sin recompilar el kernel (pregunta 7)
tools/medir.sh              mediciones de la sección 4.2 (perf, strace, bpftrace, ftrace)
tools/alucinaciones/        candidatos "alucinados" + verificador que compila contra los headers 6.8
tools/build_informe.py      genera docs/INFORME.md con las cifras REALES de evidencias/ (plantilla en tools/informe_plantilla/)
tools/sync_vm.sh, vm.sh     flujo Mac -> VM Lima
evidencias/                 salidas reales: run_tests.log, dmesg, /proc/mmguard, mediciones/, alucinaciones.txt
docs/INFORME.md             el informe (Partes I, II y III)   |   docs/ENUNCIADO.txt   el enunciado
```

## Compilar, cargar, probar y medir

Requisitos: Linux 6.x con headers (`linux-headers-$(uname -r)`), `gcc`, `make`, `python3`; para medir: `perf`, `strace`, `bpftrace`, `trace-cmd`.
**Nunca cargar el módulo en una máquina que no sea desechable** (un error de kernel detiene el sistema).

```bash
make                    # módulo + programas de usuario; compila con W=1 sin una sola advertencia
sudo ./tests/run_tests.sh   # carga el módulo, crea usuarios de prueba, corre todo (~1 min), descarga. Debe terminar en "RESULTADO FINAL: PASA"
sudo ./tools/medir.sh       # mediciones (deja las salidas crudas en evidencias/mediciones/)
make halu                   # compila los candidatos "alucinados" y guarda los errores reales

# uso manual
sudo insmod kernel/mmguard.ko                 # parámetros: verify_on_fault=1 use_vm_io=1 allow_debug=0 watch_path=""
sudo user/mmgctl add $(id -u) rw              # concede lectura/escritura al UID actual (ACL en el kernel)
user/client write 0 "mi secreto"              # mmap MAP_SHARED + msync => se sella (re-cifra)
user/client read 0 40                         # mmap + fallo de página => descifrado solo para este proceso
cat /proc/mmguard                             # contadores + últimos eventos de auditoría
sudo dmesg | grep mmguard                     # PID, UID y comando en cada evento
sudo rmmod mmguard
```

Con la VM Lima (flujo usado en el desarrollo): `tools/vm.sh 'cd ~/so-parcial3 && make && sudo ./tests/run_tests.sh'`.

Parámetros del módulo: `verify_on_fault` (1: recalcula SHA-256 de la página en cada fallo; modificable en caliente en
`/sys/module/mmguard/parameters/`), `use_vm_io` (1: marca VM_IO), `allow_debug` (1: habilita los ioctl de ataque simulado
que usan las pruebas; **apagado por defecto**), `watch_path` (prefijo de ruta que audita el kprobe).

## A qué parte del enunciado responde cada cosa

| Enunciado | Dónde |
|---|---|
| Parte I, 10 preguntas (30 %) | `docs/INFORME.md`, Parte I |
| 3.1 flujo de trabajo con IA | `docs/INFORME.md` 3.1 |
| 3.2 prompts + alucinaciones + validación | `docs/INFORME.md` 3.2, `tools/alucinaciones/`, `evidencias/alucinaciones.txt` |
| 3.3 arquitectura y trade-offs | `docs/INFORME.md` 3.3 y el diagrama de arriba |
| 4.1 código modular, Makefile sin advertencias | `kernel/`, `user/`, `Makefile` |
| 4.1 demostración de validación de permisos, cifrado/descifrado | `tests/run_tests.sh` (T01 a T04, T08), `evidencias/run_tests.log` |
| 4.1 scripts Bash/Python de ataques y carreras | `tests/run_tests.sh`, `tests/*.py`, `user/attacker.c`, `user/racer.c`, `user/stress.c` |
| 4.2 justificación teórica, medición, limitaciones | `docs/INFORME.md` Parte III, `evidencias/mediciones/` |

## Qué NO hace (honestidad)

* No cifra archivos de un sistema de archivos arbitrario: protege una **bóveda propia** expuesta como dispositivo. Interceptar `mmap` de
  cualquier archivo exigiría un LSM o integrarse al sistema de archivos (ver informe, preguntas 4 y 5). El `kprobe` solo **audita**.
* Los datos en claro están en RAM mientras un proceso autorizado los tiene mapeados: un atacante con lectura física de memoria o
  con control del kernel (otro módulo, `/dev/mem`, `/proc/kcore` con las páginas de sesión) los vería. Mitigaciones de hardware en el informe.
* Un proceso **autorizado** comprometido puede filtrar lo que lee: el módulo controla quién puede mapear, no qué hace luego con el dato.
* Solo se ha probado en aarch64 / 6.8.0-147; en x86_64 el código es el mismo salvo el acceso a argumentos del `kprobe` (hay ramas para ambas).
