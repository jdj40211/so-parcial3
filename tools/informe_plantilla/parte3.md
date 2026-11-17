---

## Parte III. Implementación, presentación y argumentación

### 4.1 Entregables de código e implementación

**Estructura (todo en `~/Projects/so-parcial3`, ver `README.md`).**

| Archivo | Líneas | Responsabilidad |
|---|---:|---|
| `include/mmguard_uapi.h` | {{L_UAPI}} | Estructuras e `ioctl` compartidos entre el módulo y los programas de usuario |
| `kernel/mmguard_main.c` | {{L_MAIN}} | Dispositivo `/dev/mmguard` (`miscdevice`), `file_operations`, ACL por UID, `ioctl`, parámetros del módulo |
| `kernel/mmguard_vm.c` | {{L_VM}} | `mmap` con validación y endurecimiento de la VMA, `vm_operations_struct` (`fault`, `page_mkwrite`, `open`, `close`), sesiones, sellado |
| `kernel/mmguard_vault.c` | {{L_VAULT}} | Bóveda: AES-256-CTR (`crypto_skcipher`), HMAC-SHA256 y SHA-256 (`crypto_shash`), nonces |
| `kernel/mmguard_audit.c` | {{L_AUDIT}} | Auditoría: `dmesg`, anillo de eventos y contadores, `/proc/mmguard` |
| `kernel/mmguard_kprobe.c` | {{L_KPROBE}} | `kprobe` de observación sobre `security_mmap_file` (opcional, por parámetro) |
| `kernel/mmguard.h`, `kernel/Makefile` | {{L_H}} | Definiciones internas y Kbuild (`W=1`) |
| `user/*.c` | {{L_USER}} | `client` (cliente autorizado), `attacker` (ataques), `racer` (carrera Dirty COW), `stress`, `mmgctl` (administración), `bench`, y la demostración de `LD_PRELOAD` |
| `tests/` | {{L_TESTS}} | `run_tests.sh` (Bash), `kcore_check.py`, `remote_read_check.py` (Python), `detector_ebpf.sh` (bpftrace) |

**Cómo funciona (resumen de las decisiones, con su razón).**

1. **Bóveda cifrada (`mmguard_vault.c`).** 16 páginas en memoria del kernel, cada una cifrada con **AES-256 en modo CTR** (en esta VM el controlador es `ctr-aes-ce`, con las extensiones criptográficas de la CPU) y **autenticada con HMAC-SHA256** (cifrar y luego autenticar), con claves distintas y aleatorias generadas al cargar (`get_random_bytes`). El IV es `nonce(64 bits) || contador(64 bits)` y el nonce sale de un contador global monótono que aumenta con **cada** cifrado de **cada** página: jamás se repite el par (clave, flujo), requisito crítico de CTR. El MAC cubre `(índice, nonce, texto cifrado)` y se verifica **antes** de descifrar. Se descartó XTS porque el MAC adicional da integridad y no solo confidencialidad (XTS no autentica).
2. **Sesión por `open()` y páginas en claro privadas (`mmguard_vm.c`).** El texto en claro solo existe en páginas propias de la sesión, creadas bajo demanda en `.fault`. No se comparte ningún marco con datos descifrados entre procesos; al cerrar se hace `memzero_explicit` antes de liberar. Para no reescribir una página que alguien ya tiene mapeada, el refresco usa *copy-on-refresh* (se descifra a una página nueva y la anterior se retira hasta que no la mapee nadie).
3. **Validación de permisos en `mmap` (`mmg_do_mmap`).** (i) El `euid` debe ser el que hizo `open()` (no sirve pasar el descriptor por `SCM_RIGHTS`); (ii) debe estar en la ACL con lectura; (iii) el rango debe caber en la bóveda; (iv) `PROT_EXEC` se rechaza; (v) `PROT_WRITE` solo con permiso `rw` y solo con `MAP_SHARED` (un COW privado crearía copias en claro que nadie sella). La ACL se vuelve a consultar **en cada fallo de página**, así que revocar un UID surte efecto de inmediato (T10).
4. **Banderas de la VMA, cada una con su razón.** `VM_DONTCOPY` (el hijo de `fork` no hereda el mapa), `VM_DONTEXPAND` (`mremap` no puede agrandarlo), `VM_DONTDUMP` (no entra en *core dumps*), `VM_IO` (get_user_pages rechaza la VMA: `ptrace`, `/proc/pid/mem` y `process_vm_readv` no leen ni escriben), `VM_MAYEXEC` siempre limpio y `VM_MAYWRITE` limpio si el mapa no nació escribible (`mprotect(+WRITE)` falla y el mapa deja de ser *COW mapping*, que cierra Dirty COW).
5. **Escritura controlada.** La VMA escribible tiene `page_mkwrite`: la PTE nace de solo lectura y la primera escritura avisa al módulo, que marca la página sucia y audita. `msync(MS_SYNC)` llega a `mmg_fsync` (por `vfs_fsync_range`), y también el cierre de la última VMA o del descriptor, y el `ioctl(SEAL)`: se **sella** (copiar, cifrar con nonce nuevo, recalcular el MAC). Antes de copiar se descartan las PTE de esas páginas con `unmap_mapping_range` (solo su rango), de modo que ninguna escritura concurrente escape al sellado.
6. **Integridad.** Dos controles independientes: el **MAC** de la bóveda (detecta que el texto cifrado en memoria del kernel cambió) y un **SHA-256 de cada página en claro** que se verifica en cada fallo (detecta que alguien escribió sobre el marco físico sin pasar por `page_mkwrite`, el efecto de un Dirty COW). Ante la segunda, la página se **repara** volviendo a descifrar desde la bóveda.
7. **Auditoría.** Cada `open`, `mmap`, fallo, rechazo, escritura, sellado, evento de integridad y acción de administración queda en `dmesg` con `pid`, `tgid`, `uid` y `comm`, en un anillo de 128 eventos y en contadores atómicos (`/proc/mmguard` y `ioctl(STATS)`). Las líneas de `dmesg` de fallos, escrituras y sellados usan `ratelimit` (una carrera genera cientos de miles de fallos por segundo); el anillo y los contadores no pierden ninguno.
8. **Orden de bloqueos y reglas de seguridad del código.** `s->lock` (sesión) → `V.lock` (bóveda); nunca se hace `copy_{from,to}_user` con un bloqueo tomado (`memdup_user` antes); el manejador de fallos no toma ningún bloqueo de tabla de páginas; toda página reservada con `__GFP_ZERO` o sobrescrita entera (sin fugas de memoria del kernel al usuario); y el texto en claro se borra al liberar.
9. **`kprobe` sobre `security_mmap_file`** (con `watch_path=...`): solo observa y registra los mapeos de archivos bajo esa ruta. No modifica registros ni el valor de retorno y **no toca la tabla de llamadas al sistema** (ver pregunta 4).

**Compilación.** `make` en la raíz compila el módulo con `W=1` y `-Wall -Wextra` usando el compilador exacto del kernel de la distribución (`aarch64-linux-gnu-gcc-13`): **cero advertencias** (solo queda la línea informativa `Skipping BTF generation ... unavailability of vmlinux`, que no es advertencia del compilador: la VM no trae `vmlinux`). Los programas de usuario compilan con `-Wall -Wextra` sin advertencias.

**Demostración de las pruebas (resultado real de `sudo ./tests/run_tests.sh` en la VM, `evidencias/run_tests.log`): {{N_PASS}} casos PASAN, {{N_FAIL}} FALLAN.** Extractos:

```text
=== T01 ===  mmreader lee: TOP-SECRET mmguard: la clave de la boveda nunca sale del kernel. Codigo de lanzamiento = 7
=== T02 ===  [OK] unauth: UID 1002: mmap SHARED -> Permission denied, mmap PRIVATE -> Permission denied (esperado EACCES)
=== T03 ===  [OK] mprotect: mprotect(+WRITE) -> Permission denied, mprotect(+EXEC) -> Permission denied
             [OK] shared-write: mmap(PROT_WRITE, MAP_SHARED) de un lector -> Permission denied (esperado EACCES)
             [INFO] control: /etc/hostname O_RDONLY + PROT_WRITE|MAP_PRIVATE -> PERMITIDO (Linux lo permite: COW privado)
             [OK] private-write: mmguard O_RDONLY + PROT_WRITE|MAP_PRIVATE -> Permission denied (esperado EACCES)
             [OK] fork: el hijo accede a la region heredada -> SIGSEGV (esperado SIGSEGV por VM_DONTCOPY)
             [OK] procmem: pwrite(/proc/self/mem) -> Input/output error; pread(/proc/self/mem) -> Input/output error; contenido intacto=si
=== T04 ===  escrito y sellado en pagina 2: DATO NUEVO del escritor autorizado
             mmreader ve: DATO NUEVO del escritor autorizado
=== T05 ===  [INFO] vault: {{T05_LINE}}
             [OK] dirtycow-vault: escrituras exitosas=0, desviaciones del contenido=0, sesion nueva ve el original=si
=== T06 ===  [INFO] control: {{T06_LINE}}
             [OK] dirtycow-control: archivo normal: el mapa privado cambio {{T06_MISM}} veces (COW legitimo) pero el ARCHIVO sigue intacto=si
=== T07 ===  [OK] integ-session: tras refallar: contenido restaurado=si, violaciones +1, reparadas +1
             [OK] integ-vault: VERIFY reporta 1 pagina(s) corrupta(s); lector nuevo -> SIGBUS; violaciones +2
=== T08 ===  [OK] kcore-coincide: los 4096 bytes en kaddr=0x... leidos de /proc/kcore coinciden con el cifrado del modulo
             [OK] kcore-entropia: entropia de Shannon = {{ENTROPY}} bits/byte (texto en claro ~ 0.2; maximo 8)
             [OK] kcore-sin-patrones: bloques de 16 bytes repetidos: 0 (el texto en claro tiene ~250 bloques en cero)
=== T09 ===  [OK] remoto-proc-mem: root no puede leer /proc/<pid>/mem en 0x...: Input/output error
             [OK] remoto-process_vm_readv: process_vm_readv -> Bad address
             [OK] vmflags: VmFlags=rd mr ms io dc de dd
=== T10 ===  [OK] revoke: antes de revocar: lee; tras revocar y refallar: SIGBUS (esperado SIGBUS)
=== T11 ===  probe_mmap: 0 -> 1   (el kprobe auditó el mmap del archivo vigilado)
=== T12 ===  dmesg: [..] mmguard: DENIEGA pid=11634 tgid=11634 uid=1002 comm=attacker mmap rechazado (uid no autorizado) prot=r-- SHARED len=4096 off=0 err=13
=== T13 ===  (sin VM_IO) [OK] dirtycow-vault: escrituras exitosas=0 ... ; [OK] ablacion-proc-mem: SIN VM_IO root SI leyo b'TOP-SECRET mmguard: la clave de '
=== T14 ===  [PASA] rmmod limpio   [PASA] dmesg sin Oops, BUG, WARNING ni bad page
```

| # | Prueba | Qué demuestra | Resultado |
|---|---|---|---|
| T01 | Cliente autorizado lee | Descifrado por fallo de página solo para el autorizado | PASA |
| T02 | UID sin permiso | `mmap` rechazado en el kernel (`EACCES`) | PASA |
| T03 | `mprotect(+WRITE/+EXEC)`, `MAP_SHARED\|PROT_WRITE`, `MAP_PRIVATE\|PROT_WRITE`, `PROT_EXEC`, `fork`, `mremap`, `/proc/self/mem` | Cada bandera de la VMA hace su trabajo | PASA (7) |
| T04 | Escritor sella con `msync`; el lector ve la versión nueva | `page_mkwrite` + sellado + coherencia entre sesiones | PASA |
| T05 | Carrera tipo Dirty COW contra la bóveda (5 s) | Cero escrituras exitosas, cero desviaciones | PASA |
| T06 | La misma carrera contra un archivo normal | Control: el ataque es real; el kernel moderno lo contiene en su capa | PASA |
| T06b | 1 escritor sellando + 2 lectores refallando (4 s) | Sin bloqueos, versión final uniforme, 0 violaciones | PASA |
| T07 | Se altera el cifrado y la página en claro a propósito | Integridad: se **detecta** y la página en claro se **repara** | PASA |
| T08 | Lectura directa de la memoria del kernel (`/proc/kcore`) | El contenido de la bóveda está **cifrado** | PASA |
| T09 | `root` lee `/proc/pid/mem` y `process_vm_readv` del autorizado | `VM_IO` bloquea la lectura desde fuera | PASA |
| T10 | Se revoca el UID con el mapa vivo | La ACL se vuelve a validar en cada fallo (`SIGBUS`) | PASA |
| T11 | `kprobe` sobre `security_mmap_file` | Auditoría de mapeos de archivos vigilados | PASA |
| T12 | `dmesg` y `/proc/mmguard` | Todos los eventos con `pid`, `uid`, `comm` | PASA |
| T12b | `bpftrace` detecta la firma del ataque | Pregunta 7 (eBPF, sin recompilar) | PASA |
| T12c | `LD_PRELOAD` frente al kernel | La defensa en usuario se elude; la del kernel no | PASA |
| T13 | Ablación sin `VM_IO` | `VM_MAYWRITE` por sí solo resiste la carrera; `VM_IO` evita la lectura desde fuera | PASA |
| T14 | `rmmod` y revisión de `dmesg` | Descarga limpia; sin Oops, BUG, WARNING ni bad page | PASA |

**Lo que no se probó o no salió.** (i) Solo se probó en aarch64 con el kernel 6.8.0-147; el código incluye ramas para x86_64 (argumentos del kprobe) pero no se compiló allí. (ii) No se usó KASAN/KCSAN/lockdep (el kernel de la VM no los trae); la ausencia de interbloqueos y carreras se apoya en las pruebas de estrés, no en un detector formal. (iii) El `kprobe` solo observa; denegar por LSM requeriría reiniciar con `bpf` en `lsm=` o recompilar. (iv) No se probó la carga ante memoria agotada (`__GFP_NOFAIL` en un único punto, la lista de páginas retiradas, es una decisión consciente que no se ejercitó en una prueba).

### 4.2 Argumentación y análisis de resultados

#### Justificación teórica: por qué en el kernel y no en espacio de usuario

1. **El acceso por puntero no pasa por ninguna capa de usuario.** Una vez que la PTE está instalada, la lectura o escritura es una instrucción de la CPU que la MMU resuelve en hardware, sin entrar en el kernel y mucho menos en una biblioteca (infograma 1.2 del enunciado). No existe en el espacio de usuario un punto donde "enganchar" un `ldr`/`str`. Lo único que el kernel hace es la parte *previa*: la VMA y el fallo de página. Por eso la defensa debe vivir allí.
2. **`LD_PRELOAD` es eludible de forma trivial, y se demostró (T12c).** La biblioteca `ldp_guard.so` envuelve `mmap()` y rechaza un archivo "protegido". Resultado real: con `mmap()` de libc queda **bloqueado**, pero (a) una **syscall directa** (`syscall(SYS_mmap, ...)` o `svc #0` en ensamblador) **no pasa por libc** y accede; (b) un **binario enlazado estáticamente** ni siquiera carga la biblioteca precargada y accede; además `LD_PRELOAD` se ignora en ejecutables `setuid`, el atacante puede simplemente no definirla (el entorno lo controla el proceso), o desmontarla con `dlclose`/parchear la GOT/PLT en su propio espacio de direcciones, porque la "defensa" corre **con los mismos privilegios y en la misma memoria que el atacante**. En cambio, las mismas dos variantes contra `/dev/mmguard` terminaron en `EACCES` (la ACL se evalúa en el kernel, con credenciales que el proceso no puede falsear).
3. **Solo el kernel ve la verdad.** Evalúa sobre objetos ya resueltos (`struct file`, credenciales, `vm_flags` finales), no sobre cadenas de usuario modificables (sin TOCTOU), y es el único que controla qué se coloca en una PTE, qué banderas tiene la VMA (`VM_MAYWRITE`, `VM_IO`) y qué páginas se pueden obtener por `ptrace`/`/proc/pid/mem`. La ACL por UID, la revocación en cada fallo, el cifrado y la protección contra la lectura desde fuera no se pueden expresar en una biblioteca.
4. **El costo es aceptable y medible** (siguiente sección): la parte "siempre encendida" son banderas (gratis), y lo caro es configurable.

#### Medición del impacto (overhead)

**Método.** Se midió en la VM Lima (aarch64, 4 CPU, 4 GiB, kernel 6.8.0-147; ver `evidencias/mediciones/entorno.txt`), con `user/bench` (microbenchmarks propios con `clock_gettime` y `getrusage`), `perf stat`, `strace -T/-c`, `bpftrace` (kprobe/kretprobe) y `ftrace` (`trace-cmd record -p function_graph`). Cada microbenchmark se repitió **{{REPS}} veces**; se informa la **mediana** y el **mínimo** (el mínimo es la mejor estimación del costo sin interferencia de la máquina anfitriona, que es una Mac compartida con otras tareas: en ejecuciones anteriores, con el anfitrión ocupado, las medianas se multiplicaron por 1.7 a 3 respecto de esta, por lo que **las razones son más confiables que los valores absolutos**). Todas las salidas crudas están en `evidencias/mediciones/`. Cada iteración trabaja sobre 16 páginas (64 KiB). Los casos comparados son el archivo normal (en la *page cache*, sin la defensa) y `/dev/mmguard` (con la defensa).

**Tabla resumen** (`evidencias/mediciones/resumen.md`):

{{TABLA_BENCH}}

Lectura de la tabla:

* **`mmap`+`munmap`** (sin tocar páginas): archivo normal **{{M_MMAP_FILE}} ns**, `mmguard` **{{M_MMAP_DEV}} ns**. El costo extra de la defensa en la llamada es de **{{D_MMAP}} ns** por `mmap`+`munmap` (validación de ACL, rango y banderas, y auditoría con `pr_info` + anillo). Es independiente del tamaño del mapa.
* **Fallo de página "caliente"** (la página en claro ya existe; se descarta la PTE y se vuelve a tocar): archivo normal **{{M_WARM_FILE}} ns** para las 16 páginas con **1 solo fallo** (*fault-around* mapea 16 páginas de una vez desde la caché), `mmguard` **{{M_WARM_DEV}} ns** con **16 fallos**: **{{M_WARM_DEV_PF}} ns por fallo** con la verificación SHA-256 de cada página y **{{M_WARM_NOV_PF}} ns por fallo** sin ella (`verify_on_fault=0`). La verificación de integridad en claro es entonces el **{{PCT_SHA}} %** del costo de un fallo caliente.
* **Fallo "frío"** (sesión nueva: se descifran las 16 páginas, con MAC, AES-256-CTR y SHA-256, más `open`/`close`): **{{M_COLD_DEV}} ns** por iteración, **{{M_COLD_DEV_PF}} ns por página**, frente a **{{M_COLD_FILE}} ns** del archivo normal (1 fallo). Es el precio del descifrado: se paga **una vez por página y por sesión**, no por acceso.
* **`pread()` de 64 KiB** (sin `mmap`): **{{M_READ}} ns**: copiar 64 KiB con `read` cuesta del mismo orden que tocar las 16 páginas del archivo normal por `mmap`; la ventaja del `mmap` (sin copia, sin cambio de contexto por acceso) se conserva en `mmguard` una vez descifradas las páginas: los accesos posteriores al fallo corren a velocidad de hardware.

**`perf stat`** (`evidencias/mediciones/perf_stat.txt`): en el caso caliente, el archivo normal produce **{{PF_FILE}}** fallos para 50 000 iteraciones y `mmguard` **{{PF_DEV}}** (16 por iteración; los fallos que se contabilizan son los de **hardware**, de ahí que la defensa no reduzca la tasa de fallos: la aumenta de 1 a 16 por iteración porque cada página se atiende por separado y no hay *fault-around*, algo necesario para descifrar y autenticar página a página). `task-clock`: **{{TC_FILE}} ms** frente a **{{TC_DEV}} ms**; los cambios de contexto son despreciables (`{{CS_DEV}}`) en ambos casos.

**`strace`** (`evidencias/mediciones/strace_T.txt`): `strace -T` mide cada `mmap` de 64 KiB con resolución de 1 µs y suma el costo de `ptrace` a ambos casos: archivo normal mediana **{{ST_FILE}} µs**, `/dev/mmguard` mediana **{{ST_DEV}} µs**; la diferencia entre ambos queda dentro del ruido del propio `strace`, por lo que **no sirve para aislar el sobrecosto de `mmap`** (para eso se usó el microbenchmark). `strace -c` confirma que el tiempo de `bench warm dev` se va en `madvise` (el descarte de la PTE), no en llamadas del módulo: el trabajo de la defensa ocurre en el manejador de fallos, que `strace` no ve.

**`bpftrace`** (`evidencias/mediciones/bpftrace.txt`, latencia por fallo medida con `kprobe`/`kretprobe`):

| Qué se mide | Promedio por llamada | Llamadas | Observación |
|---|---:|---:|---|
| `handle_mm_fault`, archivo normal (caliente) | **{{BT_FILE}} ns** | {{BT_FILE_N}} | 1 llamada por iteración (mapea 16 páginas) |
| `handle_mm_fault`, `mmguard` (caliente) | **{{BT_DEV}} ns** | {{BT_DEV_N}} | {{BT_RATIO}} llamadas por cada fallo atendido por el módulo (ver abajo) |
| Solo el callback `mmg_vm_fault`, caliente, **con** SHA-256 | **{{BT_VM_SHA}} ns** | {{BT_VM_SHA_N}} | casi todo el costo del fallo es nuestro callback |
| Solo `mmg_vm_fault`, caliente, **sin** SHA-256 | **{{BT_VM_NOSHA}} ns** | {{BT_VM_NOSHA_N}} | el costo base de ACL, bloqueo y auditoría |
| Solo `mmg_vm_fault`, frío (sesión nueva, descifra) | **{{BT_VM_COLD}} ns** | {{BT_VM_COLD_N}} | MAC + AES-CTR + SHA-256 de 4 KiB, más reservar la página |

*Observación derivada de las cuentas:* `handle_mm_fault` se invoca **dos veces por cada fallo** que llega a `mmg_vm_fault` (columna "Llamadas"), mientras que para el archivo normal es una. El histograma de `handle_mm_fault` es bimodal (una moda de 128 a 256 ns y otra de 1 a 2 µs). La explicación coherente con esos datos es que el primer intento corre con el bloqueo por VMA (6.4+), no puede completar un `.fault` de un driver que no declara ese soporte y devuelve `VM_FAULT_RETRY`; el segundo corre con `mmap_lock` y hace el trabajo. *(Es una inferencia a partir de las mediciones; no se verificó leyendo `mm/memory.c`, cuyas fuentes no están en esta VM.)* Es un costo impuesto por el kernel a cualquier `vm_ops` de driver, ajeno a la defensa.

**`ftrace`** (`evidencias/mediciones/ftrace_mmg_vm_fault.txt`) muestra el desglose de una invocación fría de `mmg_vm_fault()`: `mmg_policy_lookup` (ACL), `mutex_lock`, `alloc_pages`, `mmg_vault_read_page` → `vault_check_locked` → `vault_mac` → `hmac_*`/`sha256_ce_*` (el MAC), `vault_crypt` → `ctr-aes-ce` (el descifrado) y `mmg_digest` (el SHA-256 de la página en claro). Las duraciones con `function_graph` están infladas por la instrumentación; sirve para ver **cuál es la distribución del trabajo**, no para el valor absoluto.

**Conclusiones de la medición.** (1) `mmap` cuesta aproximadamente **{{R_MMAP}}** veces más que el de un archivo normal, en el orden de **microsegundos**; irrelevante salvo en cargas que mapean y desmapean sin parar. (2) El costo real está en el fallo de página: descifrar es un costo de **una sola vez por página y por sesión** (decenas de µs por 16 páginas), y el fallo posterior de una página ya descifrada cuesta **{{R_WARM}} veces** el de un archivo normal por página mapeada si se verifica el SHA-256, y **{{R_WARM_NOV}}** sin verificarlo. (3) Una vez instalada la PTE, el acceso no cuesta nada más: es memoria normal. (4) `verify_on_fault` es el control de **rendimiento frente a seguridad**: se puede apagar en caliente (`echo 0 > /sys/module/mmguard/parameters/verify_on_fault`) cuando se acepta no detectar la alteración del marco físico en claro.

#### Limitaciones y trabajo futuro

**Vectores que siguen descubiertos.**

1. **El texto en claro está en RAM** mientras un proceso autorizado lo tiene mapeado y, además, la clave de la bóveda vive en la memoria del kernel. Cualquiera con lectura de memoria física o con control del kernel lo ve: `root` con `/proc/kcore` (lo usamos en T08 para *demostrar* el cifrado, pero con el mismo acceso se podrían leer también las páginas de sesión y la clave), `/dev/mem` (en esta VM `CONFIG_STRICT_DEVMEM=y` lo limita), otro módulo cargado, un volcado de memoria (*kdump*), la hibernación a disco, o un ataque físico (*cold boot*, DMA). El kernel con `lockdown=confidentiality` cierra `/proc/kcore` y la carga de módulos arbitrarios, pero no estaba activo en la VM (`lockdown` figura en la lista de LSM sin modo forzado).
2. **Un proceso autorizado comprometido** puede filtrar lo que lee: `mmguard` decide quién mapea, no qué hace después con el dato (copiar a un socket, a un archivo).
3. **Canales laterales** (Spectre, Meltdown, Rowhammer, canales de caché): la memoria en claro es visible para ellos mientras la CPU la procesa.
4. **El administrador** (`CAP_SYS_ADMIN`) puede cargar contenido, cambiar la ACL y (con `allow_debug=1`) alterar páginas a propósito: es una decisión de confianza explícita, y los `ioctl` de depuración **están apagados por defecto**.
5. **La protección no cubre archivos arbitrarios**: es una bóveda propia, no un sistema de archivos cifrado ni un LSM; el `kprobe` audita pero no deniega.
6. **`VM_IO` impide la depuración legítima** del proceso (`gdb` no ve esa región); es un compromiso de seguridad, no un error.
7. **Escala**: 16 páginas fijas, ACL de 16 UID, un solo sellado por vez por sesión (un mutex); suficiente para la prueba, no para un producto.
8. **No hay un detector formal** de interbloqueos (KASAN/lockdep) en este kernel; el diseño se apoya en un orden de bloqueo documentado y en pruebas de estrés.

**Mitigaciones y trabajo futuro (hardware, hipervisor, kernel).**

* **Cifrado de memoria por hardware**: AMD **SEV/SEV-SNP** o Intel **TDX** (máquinas virtuales confidenciales), AMD SME / Intel TME y **RME/CCA** en arm64: la RAM física está cifrada con una clave que ni el hipervisor ni un volcado físico pueden usar; cubre *cold boot* y el administrador del anfitrión.
* **Etiquetado de memoria**: **MTE** de arm64 (`CONFIG_ARM64_MTE=y` en esta VM) detecta uso tras liberar y desbordamientos en los búferes de la bóveda; no es cifrado, pero reduce la superficie de errores del propio módulo.
* **Protección por claves de memoria**: **PKU** (x86) en usuario y **PKS** en kernel; el equivalente de arm64 (*Permission Overlay Extension*, kernels recientes) permitiría revocar el acceso a la región para un hilo sin tocar las PTE, incluso desde dentro del proceso autorizado.
* **IOMMU** (VT-d, SMMU): impide que un dispositivo con DMA lea o escriba las páginas de la bóveda y de la sesión.
* **Reducción de la superficie del kernel**: `lockdown=confidentiality`, módulos firmados (Secure Boot), `memfd_secret` (5.14) para sacar las páginas del mapa directo del kernel y así impedir que otro código del kernel las lea por el mapa directo, `init_on_free=1`, `CONFIG_STRICT_DEVMEM` y `/proc/kcore` cerrado.
* **Integración nativa**: reescribir la política como **LSM** (`mmap_file`, `file_mprotect`, `file_permission`) o como programa **BPF-LSM**, con `lsm=...,bpf`, para proteger archivos reales y poder **denegar**; combinarlo con `fscrypt` por directorio para cifrar en disco; y mover el sellado a `writepages` para cubrir el *writeback* de archivos reales.
* **Mejoras del módulo**: tamaño y número de bóvedas dinámicos, `mlock`/`MADV_WIPEONFORK` equivalentes para la copia en claro, rotación de claves, y un detector formal (lockdep/KCSAN) en un kernel de depuración.

### Conclusión

La solución implementa en el kernel, y no en una biblioteca, los tres mecanismos que pide el enunciado: **aislamiento** (páginas en claro privadas por sesión, VMA endurecida, ACL validada en `mmap` y en cada fallo), **detección y prevención de modificaciones no autorizadas** (`VM_MAYWRITE`/`VM_IO` frente a la carrera tipo Dirty COW, MAC y SHA-256 con reparación) y **auditoría** (`dmesg`, `/proc/mmguard`, `kprobe`). Se demostró con pruebas con controles y ablaciones que cada defensa hace lo que dice y que el ataque correspondiente era real. El costo en los fallos de página es medible y configurable. Los límites reales (texto en claro en RAM, administrador de confianza, falta de pruebas en x86 y de un detector formal de concurrencia) están declarados arriba y se atacan con hardware (SEV/TDX, MTE, PKU/PKS, IOMMU) y con integración LSM.
