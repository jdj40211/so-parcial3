# Parcial 3 de Sistemas Operativos: seguridad de archivos mapeados con `mmap()` desde la capa de kernel

**Universidad EAFIT** · Escuela de Ciencias Aplicadas e Ingeniería · Departamento de Informática y Analítica
**Asignatura:** Sistemas Operativos, periodo 2026-2
**Evaluación:** Parcial práctico-teórico (valor 25 %)
**Integrantes:** Juan David Sierra (GitHub `jdj40211`) y Andrés Prieto
**Fecha:** 17 de noviembre de 2026
**Código:** repositorio `so-parcial3` (módulo de kernel `mmguard`, programas de usuario, pruebas, mediciones y evidencias)
**Entorno de pruebas:** VM Lima `sokernel`, Ubuntu 24.04 aarch64, kernel `6.8.0-147-generic`

> Nota de método. Todas las cifras de este informe salen de archivos de `evidencias/` generados por las pruebas y mediciones reales en la VM
> (`tools/build_informe.py` rellena las cifras desde esos archivos). Los nombres de estructuras, banderas y funciones del kernel se contrastaron con los
> headers de 6.8, con `/proc/kallsyms` y con `Module.symvers`. Lo que no se logró o no se probó está dicho explícitamente en cada parte.

## Resumen ejecutivo

* **Qué se construyó.** `mmguard`: un módulo de kernel (5 archivos C, `W=1` sin advertencias) que expone `/dev/mmguard`, una bóveda de 16 páginas **cifradas en la memoria del kernel** (AES-256-CTR + HMAC-SHA256). El texto en claro solo se crea, página por página, en el manejador de fallos y solo para procesos autorizados por una ACL de UID, en páginas privadas de cada sesión. La VMA se endurece (`VM_MAYWRITE`/`VM_MAYEXEC` limpios, `VM_DONTCOPY|VM_DONTEXPAND|VM_DONTDUMP|VM_IO`), las escrituras pasan por `page_mkwrite` y se **sellan** (re-cifran) con `msync`, y todo queda auditado.
* **Resultado de las pruebas.** `run_tests.sh`: **52 casos PASAN, 0 FALLAN**, con descarga limpia y `dmesg` sin errores del kernel. Incluye: UID no autorizado rechazado, `mprotect`/`MAP_SHARED|PROT_WRITE`/`PROT_EXEC` rechazados, ataque de carrera tipo Dirty COW resistido (0 escrituras exitosas de 11 555 318 intentos), modificación indebida detectada y reparada, contenido de la memoria del kernel verificado **cifrado** por `/proc/kcore`, y `LD_PRELOAD` eludido mientras el kernel no.
* **Costo medido.** `mmap`+`munmap` ≈ 1479 ns (archivo normal 831 ns); fallo "caliente" ≈ 2058 ns por página (522 ns sin la verificación SHA-256); descifrado "frío" ≈ 4261 ns por página, una vez por página y por sesión. Después del fallo, el acceso es memoria normal.
* **Límites.** Probado solo en aarch64 / 6.8.0-147; el texto en claro está en RAM mientras se usa; el `kprobe` solo audita; un administrador es de confianza. Ver "Limitaciones y trabajo futuro".

**Contenido:** Parte I (10 preguntas) · Parte II (estrategia con IA: 3.1, 3.2, 3.3) · Parte III (implementación, resultados, mediciones, argumentación, limitaciones).

---

## Parte I. Análisis conceptual (preguntas diagnósticas)

Convenciones. Los nombres de estructuras, banderas y funciones se verificaron contra los headers del kernel **6.8.0-147-generic** (`/lib/modules/6.8.0-147-generic/build/include`), contra `/proc/kallsyms` del kernel en ejecución (para saber si una función existe y si es global `T` o local `t`) y contra `Module.symvers` (para saber si se exporta). Donde dice "medido" o "observado" el dato sale de una ejecución real en la VM (aarch64); donde se describe código interno de `mm/*.c` que los headers no incluyen, se describe el comportamiento y se confirma la existencia de la función en `kallsyms`. La arquitectura de referencia de los ejemplos de bits es arm64 (la de la VM), con la equivalencia en x86_64 entre paréntesis.

### 1. Secuencia exacta desde `mmap()` hasta el primer fallo de página

**Fase A: la llamada `mmap()` no toca la memoria.**

1. libc ejecuta la instrucción de llamada al sistema (`svc #0` en arm64, `syscall` en x86_64). La CPU sube a Ring 0 (EL1) y salta al vector de excepciones; el kernel despacha la syscall `mmap` hacia `ksys_mmap_pgoff()`.
2. Si el mapeo es de archivo se resuelve `fget(fd)` (se obtiene la `struct file`); luego `vm_mmap_pgoff()` llama a `security_mmap_file(file, prot, flags)` (el hook LSM `mmap_file`, ver pregunta 4) y toma `mmap_write_lock(mm)`.
3. `do_mmap()` valida argumentos, elige la dirección con `get_unmapped_area()` y traduce `prot`/`flags` en `vm_flags`: `PROT_READ` a `VM_READ | VM_MAYREAD`, `MAP_SHARED` a `VM_SHARED | VM_MAYSHARE`, etc. Aquí se aplican las reglas de la pregunta 8 (por ejemplo, un `MAP_SHARED` sobre un descriptor sin `FMODE_WRITE` pierde `VM_MAYWRITE`/`VM_SHARED`).
4. `mmap_region()` reserva un `struct vm_area_struct` (`vm_area_alloc`), rellena `vm_start`, `vm_end`, `vm_pgoff` (desplazamiento en páginas dentro del archivo), `vm_file`, `vm_flags`, y **llama a `file->f_op->mmap(file, vma)`**. Para un archivo normal eso instala `vma->vm_ops = &generic_file_vm_ops` (cuyo `.fault` es `filemap_fault`); para un dispositivo es el código del driver (en `mmguard`, `mmg_do_mmap()`, que valida la ACL y endurece la VMA). Después `vma_set_page_prot()` calcula `vm_page_prot` (los bits de protección que tendrán las PTE) con `vm_get_page_prot(vm_flags)`, y la VMA se inserta en el árbol de VMAs del proceso (`mm->mm_mt`, un *maple tree* desde 6.1).
5. `mmap_write_unlock` y retorno de la dirección. **No se creó ninguna PTE**: solo existe una promesa registrada en la VMA (salvo `MAP_POPULATE`, que invoca `mm_populate()`). Por eso `mmap` de 16 páginas cuesta del orden de 1 µs en las mediciones de la Parte III, independientemente del tamaño.

**Fase B: el primer acceso.**

6. La CPU ejecuta `ldr`/`str` sobre una dirección virtual del rango. La **MMU** consulta la TLB; si falla, el hardware recorre la tabla de páginas desde la base (arm64: `TTBR0_EL1`; x86_64: `CR3`) por los niveles PGD, (P4D plegado), PUD, PMD y PTE (4 niveles con páginas de 4 KiB). Como el kernel todavía no instaló la entrada final, esta es inválida (bit *valid* en 0 en arm64, *present* en 0 en x86).
7. La MMU no puede traducir: lanza una excepción síncrona. En arm64 es un *data abort* por fallo de traducción (el registro `FAR_EL1` guarda la dirección y `ESR_EL1` el motivo y si fue lectura o escritura); el vector entra por `do_mem_abort()` → `do_translation_fault()` → `do_page_fault()` (todas presentes en `kallsyms`). En x86_64 es la excepción #PF (vector 14, dirección en `CR2`) hacia `exc_page_fault()` → `do_user_addr_fault()`.
8. El manejador busca la VMA que contiene la dirección: primero con el bloqueo por VMA (`lock_vma_under_rcu()`, desde 6.4, evita `mmap_lock`) y, si no se puede, con `mmap_read_lock()` + `find_vma()`. Sin VMA: `SIGSEGV` con `SEGV_MAPERR`. Con VMA, se comprueba que el tipo de acceso esté permitido por `vm_flags` (`VM_READ`/`VM_WRITE`/`VM_EXEC`); si no: `SIGSEGV` con `SEGV_ACCERR`. Esto sucede **antes** de cualquier llamada al driver, y es el motivo por el que `PROT_EXEC` ausente basta para bloquear la ejecución.
9. `handle_mm_fault()` (símbolo global en `kallsyms`) asigna los niveles de tabla que falten (`p4d_alloc`, `pud_alloc`, `pmd_alloc`) y llega a `handle_pte_fault()`. Con PTE vacía llama a `do_pte_missing()`: si la VMA es anónima, `do_anonymous_page()` (página de ceros); si no, `do_fault()` que, según el acceso, elige `do_read_fault()` (que antes intenta `->map_pages` para mapear varias páginas contiguas, *fault-around*), `do_cow_fault()` (escritura en privado) o `do_shared_fault()` (escritura en compartido).
10. Esos caminos terminan en `__do_fault()`, que ejecuta **`vma->vm_ops->fault(vmf)`** con un `struct vm_fault` que trae `vma`, `pgoff` (página dentro del archivo), `address` y `flags` (`FAULT_FLAG_WRITE`, `FAULT_FLAG_REMOTE`, …). Para archivos, `filemap_fault()` busca la página en la *page cache*; si no está, dispara lectura (con *readahead*) y el fallo es **mayor** (`VM_FAULT_MAJOR`, bloquea por E/S); si está, es **menor**. En `mmguard` este es el punto donde se descifra una página.
11. El callback devuelve la página en `vmf->page`; el kernel la bloquea si hace falta, `finish_fault()` instala la **PTE** (dirección física + bits de `vm_page_prot`), actualiza `rmap`, contadores (`MM_FILEPAGES`) y la TLB; `handle_mm_fault` devuelve `VM_FAULT_*` y el manejador de arquitectura retorna.
12. La CPU **reejecuta la misma instrucción**, ahora con traducción válida: el acceso se completa sin entrar otra vez al kernel (hasta que la PTE se descarte). Una escritura sobre una PTE de solo lectura pero con VMA escribible produce otro fallo (por protección), que se resuelve con `do_wp_page()` o `page_mkwrite` (preguntas 3 y 6).

*Lo que muestra el módulo.* `dmesg` registra, con `FALLO pid=… pagina=0 va=0xf9ea58a2d000 lectura`, la dirección virtual del fallo; el contador `fallos_de_pagina` de `/proc/mmguard` sube exactamente una vez por página tocada tras el `mmap`, no en el `mmap` (T01 y T04 de `evidencias/run_tests.log`).

### 2. `MAP_SHARED` frente a `MAP_PRIVATE` en `vm_area_struct`

La diferencia se codifica en **`vm_flags`**, no en un campo propio: `VM_SHARED` (y `VM_MAYSHARE`, que recuerda que el mapa *nació* compartido) para `MAP_SHARED`; su ausencia para `MAP_PRIVATE`. En ambos casos `vm_file` y `vm_pgoff` identifican el archivo y el desplazamiento, y `vm_ops` el comportamiento (`fault`, `page_mkwrite`, …). `is_cow_mapping(flags)` (en `mm.h`: `(flags & (VM_SHARED | VM_MAYWRITE)) == VM_MAYWRITE`) es la definición literal de "mapa con COW": **privado y potencialmente escribible**.

* **`MAP_SHARED`**: la VMA se enlaza al `address_space` del archivo (`i_mmap`, un árbol de intervalos que permite a `rmap` encontrar todas las VMAs de una página) y las PTE apuntan a las páginas de la *page cache*, las mismas que ve cualquier otro proceso y `read()`/`write()`. Las escrituras modifican la página compartida; el kernel la marca sucia y la persiste en el archivo (preguntas 6). Si la VMA tiene `vm_ops->page_mkwrite`, `vma_wants_writenotify()` hace que la PTE nazca de solo lectura para poder avisar en la primera escritura (así lo usa `mmguard`).
* **`MAP_PRIVATE`**: las PTE nacen de solo lectura aunque la VMA sea escribible (`vm_get_page_prot` quita el bit de escritura para mapas privados). La primera escritura provoca el COW (pregunta 3): se copia la página a memoria **anónima** (`anon_vma`), propia del proceso, que nunca vuelve al archivo.

*Observado en este trabajo* (campo `flags_vma` de la auditoría de `mmguard`): un mapa `MAP_SHARED` sobre un descriptor abierto `O_RDONLY` llega al driver con `0x4064091` (`VM_READ|VM_MAYREAD|VM_MAYSHARE` más las banderas del módulo; **sin `VM_SHARED` ni `VM_MAYWRITE`**: el kernel los quita porque el descriptor no puede escribir), mientras que con `O_RDWR` llega con `0x4064099` (con `VM_SHARED`). Es decir, el permiso del `open()` condiciona la VMA desde el inicio.

*Implicaciones de seguridad.*
* **Persistencia**: en compartido, lo que escribe un proceso termina en disco (por *writeback*, sin que haya llamado a `write()`), incluso si el proceso muere; en privado nunca persiste.
* **Visibilidad cruzada**: en compartido, todos los que mapean el archivo ven los cambios al instante (un proceso malicioso puede alterar datos que otro está parseando: ventana de carrera TOCTOU). En privado, mientras la página no se haya copiado, el proceso **sigue viendo los cambios que otros hagan al archivo** (Linux no garantiza una instantánea), y después de copiar ya no.
* **Fugas por la caché compartida**: como la *page cache* es común, un proceso puede sondear qué páginas de un archivo están residentes (`mincore`, `cachestat`) y construir canales laterales; por eso `mincore` se endureció en la serie de kernels 5.0 a 5.2 (solo informa de páginas de archivos que el llamador puede escribir o ya tiene mapeadas).
* **Anónimo compartido** (`MAP_SHARED|MAP_ANONYMOUS` = `shmem`) sobrevive al `fork`: es un canal de comunicación entre padre e hijo, y por eso `mmguard` pone `VM_DONTCOPY`.

### 3. Ciclo de vida COW y cómo la mala gestión de banderas escala privilegios

**Ciclo de vida de una página bajo COW (mapa privado de archivo).**

1. *Mapeo*: la VMA es privada, `VM_MAYWRITE` puede estar activo, pero la PTE se instala **sin** permiso de escritura (aunque `PROT_WRITE` esté pedido).
2. *Lectura*: el fallo mapea la página de la *page cache* en solo lectura. `struct page` cuenta una referencia más y `mapcount` aumenta; la página sigue siendo "del archivo".
3. *Primera escritura*: la CPU lanza un fallo de protección (PTE presente pero sin escritura). `handle_pte_fault()` → `do_wp_page()` (local, `t`, en `kallsyms`) → `wp_page_copy()`: reserva una página anónima nueva, copia los 4 KiB, instala una PTE **escribible y sucia** que apunta a la copia (marcada `PageAnonExclusive`, 5.19+), actualiza `rmap` (de archivo a anónimo) y suelta la referencia a la página de la caché. El archivo **no** cambia.
4. *Escrituras siguientes*: la PTE ya permite escribir; no hay más fallos.
5. *`fork()`*: padre e hijo comparten la copia anónima otra vez en solo lectura; la primera escritura de cualquiera repite el ciclo. Si la página es exclusiva (`PageAnonExclusive`, `mapcount == 1`) `do_wp_page()` la **reutiliza** sin copiar (`wp_page_reuse()`).
6. *Fin*: `munmap`/`exit` liberan la copia, o se envía a *swap* (con el riesgo de dejar datos en claro fuera de la RAM, ver pregunta 8).

**Cuándo un error en las banderas de protección escala privilegios.** La invariante es: *una escritura a un mapa privado jamás debe llegar a la página de la caché del archivo*. Se rompe en estos casos:

* **Dirty COW (CVE-2016-5195).** `/proc/self/mem` y `ptrace` escriben con `get_user_pages(FOLL_WRITE | FOLL_FORCE)`, que está **permitido** sobre un mapa de solo lectura si es COW (`VM_MAYWRITE` activo, `is_cow_mapping`): sirve para depurar. El código antiguo resolvía el COW (`faultin_page`), pero luego *quitaba* `FOLL_WRITE` y repetía la búsqueda en modo lectura apoyándose en que la copia ya existía. Si un segundo hilo ejecutaba `madvise(MADV_DONTNEED)` justo entre ambos pasos, la copia desaparecía, la segunda búsqueda devolvía la página **original de la caché** y la escritura forzada caía sobre ella: se alteraba un archivo de solo lectura (`/etc/passwd`, un binario `setuid`) y el *writeback* lo grababa. El parche de 2016 introdujo `FOLL_COW` y una comprobación del bit sucio; en series posteriores se eliminó ese truco (**en los headers 6.8 `FOLL_COW` ya no existe**: `grep -c FOLL_COW include/linux/mm.h` = 0) y se rastrea la exclusividad con `PageAnonExclusive`.
* **`VM_MAYWRITE` indebido en un mapa compartido de solo lectura**: permitiría `mprotect(PROT_WRITE)` y escribir en la caché de un archivo para el que solo hay permiso de lectura. Por eso el kernel limpia `VM_MAYWRITE` si el descriptor no tiene `FMODE_WRITE`, y por eso `mmguard` lo limpia siempre que el mapa no nace escribible.
* **Familia relacionada, otro mecanismo**: Dirty Pipe (CVE-2022-0847) no usa `mmap`, pero tiene el mismo efecto (escribir en la caché de un archivo de solo lectura) por una bandera mal inicializada (`PIPE_BUF_FLAG_CAN_MERGE`). Ambos casos son "una bandera de permiso con valor equivocado".

*Qué hace `mmguard`.* `mmg_do_mmap()` limpia `VM_MAYWRITE` cuando el mapa no nació escribible, de modo que `is_cow_mapping()` es falso: aun si algún camino hiciera `FOLL_FORCE`, `check_vma_flags()` lo rechaza (`!is_cow_mapping` → `-EFAULT`). Además pone `VM_IO`, que hace que GUP rechace la VMA completa. La prueba **T05** lanza el ataque durante 5 s: `0` escrituras exitosas de `11 555 318` intentos y `0` desviaciones del contenido (en `evidencias/run_tests.log`). La prueba **T13** repite la carrera con `use_vm_io=0` (solo la capa `VM_MAYWRITE`): `0` escrituras exitosas de `7 718 717`. El **control T06** (archivo normal en el mismo kernel) muestra que el kernel moderno también es inmune, de otra manera: `2 141 809` escrituras por `/proc/self/mem` **sí** tienen éxito, pero van a la copia privada (el mapa cambió `828 293` veces) y el **archivo permanece intacto**.

### 4. Hook en la `sys_call_table` (LKM) frente a un LSM con `file_mmap`

**Nota de nombres.** El enunciado dice `file_mmap`; en 6.8 el hook se llama **`mmap_file`** (`include/linux/lsm_hook_defs.h`: `LSM_HOOK(int, 0, mmap_file, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)`) y el envoltorio que invoca el kernel es `security_mmap_file()` (símbolo global presente en `kallsyms`). Hay además `mmap_addr` y `file_mprotect`.

| Criterio | LKM + parche a `sys_call_table` | LSM (`mmap_file`, `file_mprotect`) |
|---|---|---|
| **Viabilidad en 6.8** | Muy baja. `kallsyms_lookup_name()` dejó de exportarse (5.7): el intento de usarla **no enlaza** (`ERROR: modpost: "kallsyms_lookup_name" [cand.ko] undefined!`, `evidencias/alucinaciones.txt`). `sys_call_table` no está en `Module.symvers`. La tabla vive en memoria de solo lectura tras el arranque | Alta como diseño, pero **no se carga como módulo**: los LSM se registran en el arranque (`security_add_hooks`). Hay que compilarlo dentro del kernel (o usar BPF-LSM) |
| **Cobertura** | Solo ve el punto de entrada de la syscall. No ve `mmap` hechos por el kernel mismo (el cargador ELF en `execve` llama a `vm_mmap`), ni `io_uring`, ni mmap de otras personalidades (compat 32 bits) | `security_mmap_file()` se invoca desde `vm_mmap_pgoff()`: **casi todos** los caminos que crean un mapa de archivo pasan por él (syscall `mmap`, cargador ELF, `vm_mmap`) |
| **Datos disponibles** | Argumentos crudos en memoria de usuario (cadenas de ruta, descriptores): **TOCTOU** (el usuario los cambia entre la inspección y el uso) | Objetos ya resueltos del kernel (`struct file`, inodo, credenciales, `prot`/`flags` finales): sin TOCTOU |
| **Seguridad del propio hook** | Exige apagar protecciones: en x86 el bit WP de CR0 (`write_cr0`), que desde 5.3 el kernel *fija* (*CR pinning*); en arm64 ni existe ese registro (compilar `write_cr0` **falla**: `implicit declaration of function 'write_cr0'`). Con varios núcleos hay una ventana en la que otro CPU escribe en memoria de solo lectura. Cualquier error rompe todas las syscalls del sistema | API estable y soportada, con semántica de denegación (`return -EACCES`) |
| **Permite denegar** | Sí, pero reemplazando la syscall entera (frágil) | Sí, de forma nativa |
| **Mantenimiento y apilado** | Choca con otros módulos que parchean lo mismo; sin orden definido | LSM apilables (`lsm=` en el arranque) |
| **Auditoría de seguridad (Secure Boot, *lockdown*)** | Con *lockdown* o Secure Boot no se carga módulo no firmado, y los parches están pensados para impedirse | Es el mecanismo que SELinux, AppArmor y Landlock ya usan |

*Qué elegí y por qué.* En la VM los LSM activos son `lockdown,capability,landlock,yama,apparmor` y `CONFIG_BPF_LSM=y` está compilado pero **no activo** (habría que añadir `bpf` a `lsm=` en la línea de arranque y reiniciar). Como el entregable tenía que cargarse en caliente y sin reiniciar, la solución combina: (1) un **dispositivo de caracteres con su propio `mmap`** (la intervención ocurre en `vm_ops`, que no es opcional para quien usa el dispositivo), (2) un **kprobe de solo observación sobre `security_mmap_file`** para auditar mapeos de una ruta (T11: `probe_mmap: 0 -> 1`), y (3) la descripción de cómo sería el LSM definitivo. **No se toca la tabla de llamadas al sistema**: ni se puede localizar de forma soportada, ni se puede escribir sin desactivar defensas, y el beneficio no compensa el riesgo de romper todo el sistema.

### 5. Cifrado transparente y la *page cache*

Si el archivo está cifrado en disco, hay dos preguntas distintas: **dónde** se descifra y **quién puede ver** el texto en claro.

*Qué hacen los sistemas de archivos reales.* Con `fscrypt` (compilado en esta VM: `CONFIG_FS_ENCRYPTION=y`) o con cifrado de bloque (dm-crypt), el flujo de un fallo de lectura es: `filemap_fault()` → la página no está en la caché → el sistema de archivos emite la lectura (`->read_folio`/`->readahead`) → el bloque llega **cifrado** del disco → en la finalización de la E/S (`bio` *endio*, p. ej. `fscrypt_decrypt_bio()`) se **descifra en sitio** → la página queda `Uptodate` y se mapea. Es decir: **la *page cache* guarda el texto en claro**; el cifrado vive solo entre la caché y el dispositivo. En la escritura ocurre lo contrario: `->writepages` cifra a una página temporal (`fscrypt_encrypt_pagecache_blocks`) y es esa copia la que va al disco.

*Consecuencia.* Como la caché es compartida, cualquier proceso que pueda abrir y mapear el archivo (según permisos DAC/LSM) ve esas mismas páginas en claro, y también las ve un volcado de memoria física. Para que **solo el espacio de usuario autorizado** vea el texto sin exponerlo a otros no privilegiados, la proyección no puede servirse de la caché compartida, así que hay tres técnicas:

1. **Páginas descifradas privadas por proceso** (lo que hace `mmguard`): el `->fault` del driver devuelve una página propia de la sesión, descifrada bajo demanda; la versión que vive en el kernel permanece cifrada y autenticada. Dos procesos jamás comparten un marco con datos descifrados, y al cerrar se hace `memzero_explicit` antes de liberar. Demostración: **T08** lee la memoria del kernel por `/proc/kcore` en la dirección de la bóveda: entropía `7.950` bits/byte, `0` bloques repetidos de 16 bytes (el texto en claro tendría unos 250 en cero), no aparece "TOP-SECRET".
2. **Quitar la página del mapa directo del kernel** (`memfd_secret`, 5.14): el contenido no es accesible ni para el propio kernel por el mapa directo.
3. **Cifrado de memoria por hardware** (SME/TME en x86, SEV/TDX en nubes, RME en arm64): la RAM física está cifrada; protege del volcado físico, no de un proceso con permisos.

*Control del acceso dentro del kernel.* La validación debe repetirse en cada fallo (no solo en `mmap`), porque la VMA persiste aunque el permiso se revoque: T10 revoca el UID en la ACL y el siguiente fallo termina en `SIGBUS` (`UID revocado en la ACL -> SIGBUS`). Se bloquea también la lectura "desde fuera": T09 muestra que `root` no puede leer el texto del proceso autorizado por `/proc/<pid>/mem` ni por `process_vm_readv` (`Input/output error` y `Bad address`) gracias a `VM_IO`; el ablativo T13 confirma que **sin** `VM_IO` ese acceso sí funciona, o sea que la bandera es una capa necesaria.

### 6. `msync`/`fsync`, páginas sucias y evasión de filtros

**Cómo garantiza el kernel la consistencia.** Una escritura por una PTE activa pone el bit *dirty* de la PTE (hardware, o *software dirty* en arm64 sin DBM). En un mapa compartido con *write-notify*, la primera escritura pasa por `page_mkwrite()` (donde el sistema de archivos reserva bloques) y la página queda marcada con `PG_dirty` y la etiqueta `PAGECACHE_TAG_DIRTY` en el `address_space`. Luego:

1. El *writeback* periódico (hilos `kworker` de `wb_workfn()`) escribe las páginas sucias cuando superan `dirty_background_ratio` o `dirty_expire_centisecs` (30 s por defecto). Antes de escribir, `folio_mkclean()` (global en `kallsyms`) recorre la `rmap` para **volver a proteger las PTE y recoger el bit dirty**, de modo que una escritura posterior vuelva a notificar. La página pasa `PG_dirty` → `PG_writeback` → limpia al completarse la E/S.
2. `msync(MS_SYNC)` sobre un mapa compartido llega a `vfs_fsync_range()` → `->fsync` del archivo: escribe y espera las páginas sucias del rango, confirma el diario y vacía la caché del dispositivo. `msync(MS_ASYNC)` hoy no hace nada útil (valida argumentos). `fsync(fd)` y `msync(MS_SYNC)` son el único punto en que el programa obtiene garantía de durabilidad; sin ellos, ante un fallo de energía puede persistir un subconjunto de las páginas.

*Mismo camino en `mmguard`*: `msync(MS_SYNC)` llega a `mmg_fsync()` (lo comprobamos: `ESCRIBE … marcada sucia` y `SELLA … re-cifradas` en `dmesg`, T04), que **sella** la página (re-cifra con nonce nuevo y recalcula el MAC). Hasta el sellado, el cambio vive solo en la página privada de la sesión: no es visible para otros ni se persiste.

**Cómo evade filtros un atacante si no se inspecciona al escribir.** Los filtros clásicos viven en la ruta de E/S de usuario: `write()`/`pwrite()` (hooks `file_permission`, fanotify con permiso, un proxy en espacio de usuario o `LD_PRELOAD`). Una **escritura por mapeo es una simple instrucción `str`**: nunca pasa por la syscall `write`, así que esos filtros no la ven. El contenido llega a disco por *writeback* del kernel, cuando el proceso ya puede haber terminado. Variantes: (a) pasar el filtro con datos inocuos y modificar la página mapeada después (TOCTOU, la página compartida cambia bajo los pies del inspector); (b) escribir y no llamar nunca a `msync` (el kernel lo grabará igual); (c) usar `/proc/self/mem` o Dirty COW para alterar páginas sin que ninguna VMA sea escribible. Los puntos donde sí se puede inspeccionar son `page_mkwrite` (notificación de la primera escritura), el *writeback* (`->writepages`) y la finalización de la E/S, y la barrera de seguridad de la bóveda es no confiar en el contenido hasta el **sellado con MAC**.

### 7. Control con eBPF (`kprobe`/`fexit`)

eBPF permite adjuntar programas verificados a puntos de instrumentación del kernel en ejecución, sin recompilar ni reiniciar (requiere `CAP_BPF`/`CAP_PERFMON`):

* **Qué se engancha.** `kprobe:security_mmap_file` (cada `mmap` de archivo, con `file`, `prot`, `flags`), `fentry/fexit:do_mmap` o `mmap_region` (con *BTF*, `fexit` da los argumentos y el valor de retorno tipados), tracepoints `syscalls:sys_enter_madvise`/`sys_enter_mprotect`/`sys_enter_mmap`, y `kprobe:mem_rw` (el camino de `/proc/<pid>/mem`, presente en `kallsyms` de esta VM).
* **Qué se registra.** Mapas hash por `pid`/`comm`/`(dev,ino)` con contadores; histogramas de latencia; un `ringbuf` que entrega eventos al espacio de usuario. El `file->f_inode` permite comparar con inodos sensibles sin depender de cadenas de ruta.
* **Patrones anómalos.** (1) La firma de Dirty COW: decenas de miles de `madvise(MADV_DONTNEED)` por segundo junto con escrituras `/proc/self/mem` del **mismo** proceso; (2) `mprotect` que agrega `PROT_EXEC` a un mapa de archivo (carga de código); (3) un mismo PID que mapea muchos archivos sensibles distintos en poco tiempo (exfiltración); (4) tasa de fallos mayores atípica.
* **Demostración propia (T12b).** El script `tests/detector_ebpf.sh` usa `bpftrace` (eBPF) con dos sondas durante la carrera: en un segundo vio `2 607 331` `madvise(DONTNEED)` y `1 545 313` escrituras a `/proc/pid/mem` del proceso `racer`, y dispara la alerta. Todo sin tocar el kernel ni recompilar.
* **Límites.** Un programa kprobe/tracepoint **observa**, no puede negar. Para denegar hay que usar BPF-LSM (`SEC("lsm/mmap_file")` devolviendo `-EPERM`, 5.7+), que en esta VM está compilado pero no habilitado en `lsm=`. El verificador limita bucles y accesos; los eventos pueden perderse si el `ringbuf` se llena; un atacante con `CAP_BPF` puede desactivar al vigilante.

### 8. `O_RDONLY` con `PROT_READ | PROT_WRITE` y `MAP_PRIVATE`

**Sí, Linux lo permite en una configuración normal.** En `do_mmap()` el caso `MAP_PRIVATE` solo exige que el archivo se pueda **leer** (`FMODE_READ`), y marca `VM_MAYWRITE`; el exigir `FMODE_WRITE` está únicamente en la rama `MAP_SHARED` con `PROT_WRITE`. La razón es semántica y viene de POSIX: un mapa privado no propaga los cambios al archivo (los hace sobre una copia anónima), así que no necesita permiso de escritura sobre el archivo. Es lo que usan el cargador dinámico (relocaciones sobre las páginas de `.data`) y los depuradores.

*Evidencia propia.* En `attacker private-write` (T03) el control `open("/etc/hostname", O_RDONLY)` + `mmap(PROT_READ|PROT_WRITE, MAP_PRIVATE)` devuelve **PERMITIDO**; en cambio el mismo patrón sobre `/dev/mmguard` devuelve `Permission denied` (`mmap rechazado (PROT_WRITE sin permiso de escritura)` en la auditoría).

*Riesgos.*
1. **Alteración temporal de datos**: el proceso puede modificar *su copia* (por ejemplo parchear un binario antes de ejecutarlo con `PROT_EXEC`, o alterar datos que luego parsea), sin dejar rastro en el archivo ni requerir ningún permiso de escritura: los controles basados solo en "¿puede escribir el archivo?" no lo detectan.
2. **Visibilidad desigual**: antes de copiar una página el proceso sigue viendo cambios hechos al archivo por otros (lectura inconsistente entre páginas copiadas y no copiadas).
3. **Fuga de información**: las copias son memoria anónima y pueden ir a *swap* o a un volcado (*core dump*) en claro (si el contenido se había descifrado, quedaría descifrado). Por eso `mmguard` marca `VM_DONTDUMP`, y las páginas de la sesión no son memoria de usuario paginable (no están en las listas LRU, por lo que nunca se envían a *swap*).
4. **Superficie de explotación**: es el escenario en el que se apoya Dirty COW y los fallos similares; el mapa tiene `VM_MAYWRITE` aunque el descriptor sea de solo lectura.
5. **Consumo de memoria**: cada página escrita duplica memoria.

*Defensa en `mmguard`*: se rechaza `PROT_WRITE` con `MAP_PRIVATE` para todos (un COW privado crearía copias en claro que nadie selló ni auditó), y `VM_MAYWRITE` se limpia cuando el mapa no nace escribible.

### 9. Carreras entre `madvise(MADV_DONTNEED)` y escrituras en páginas privadas

`MADV_DONTNEED` ejecuta `zap_page_range_single()` (global en `kallsyms`) sobre el rango, que **descarta las PTE y libera las páginas anónimas privadas**; la siguiente lectura obtendrá una página de ceros (anónimo) o la del archivo (mapa de archivo). Importa que `madvise_need_mmap_write()` devuelve falso para `MADV_DONTNEED`: corre bajo `mmap_read_lock`, **concurrente** con los fallos de página y con GUP. El kernel actual evita la carrera con capas superpuestas:

1. **Bloqueo de tabla de páginas (PTL).** Cada modificación de una PTE ocurre con `pte_offset_map_lock()`; el zap y el fallo se serializan por página de tabla.
2. **Revalidación tras el bloqueo.** El camino de COW (`wp_page_copy()`) copia la página **sin** tener el PTL, y al volver a tomarlo comprueba `pte_same(*vmf->pte, vmf->orig_pte)`: si el `madvise` cambió la PTE mientras tanto, abandona y devuelve para **reintentar** el fallo desde cero.
3. **GUP ya no "adivina".** El camino de Dirty COW (preguntas 3 y 5) hacía una segunda búsqueda sin escritura; hoy `__get_user_pages()` conserva `FOLL_WRITE`: si la PTE no es escribible, vuelve a llamar a `faultin_page()` y **repite**, de modo que cada intento de escritura termina en una página privada ya COWed y escribible (`FOLL_COW` desapareció, verificado en 6.8). Si el `madvise` la descarta, el bucle crea otra copia; la escritura jamás llega a la página de la caché.
4. **Contabilidad de exclusividad.** `PageAnonExclusive`/`mapcount`/refcount deciden si una página anónima puede reutilizarse sin copiar, evitando que una página compartida (por `fork` o por GUP con *pin*) se escriba directamente.
5. **Bloqueo por VMA (6.4+).** Los fallos usan `lock_vma_under_rcu()` (bloqueo de lectura por VMA); `mprotect`/`munmap`/`mremap` toman el bloqueo de escritura de esa VMA, por lo que no cambian los permisos de una VMA bajo los pies de un fallo.

*Evidencia propia.* **T06** (control en archivo normal): `2 141 809` escrituras con `pwrite` a `/proc/self/mem` y `11 802 974` `madvise(DONTNEED)` concurrentes durante 5 s; todas las escrituras tuvieron éxito **en la copia privada** (el mapa cambió `828 293` veces), `0` señales y el archivo quedó intacto. **T05**: la misma carrera contra `mmguard` produce `0` escrituras exitosas y `0` cambios de contenido, y la sesión nueva ve el original.

### 10. `struct page`, tablas de páginas y bits de protección frente a la inyección de código

* **`struct page`** (hoy se opera con `struct folio`) es el descriptor de **cada marco físico** (el arreglo `memmap`): `flags` (`PG_dirty`, `PG_locked`, `PG_anon_exclusive`, …), contador de referencias, `_mapcount` (en cuántas PTE aparece), `mapping`/`index` (a qué archivo o `anon_vma` pertenece). Es la fuente de verdad para `rmap` (de página a todas las PTE que la mapean, usada por el *writeback* y por el *reclaim*), para COW (`PageAnonExclusive`) y para saber cuándo un marco puede liberarse o reutilizarse. Un marco con referencias de un mapeo no se libera: el kernel no puede entregar a otro proceso la memoria que alguien todavía tiene mapeada.
* **Tablas de páginas** (PGD, P4D, PUD, PMD, PTE): la jerarquía que la MMU recorre. Cada proceso tiene su propia raíz, que es la base del **aislamiento**: una dirección virtual de otro proceso no tiene camino de traducción en mi jerarquía. El kernel solo instala PTE que correspondan a VMAs válidas (un proceso no puede fabricar una PTE hacia un marco ajeno).
* **Bits de protección de la MMU**, copiados desde `vm_page_prot`: en arm64 (`pgtable-hwdef.h`, verificado) `PTE_USER` (bit 6, AP[1]), `PTE_RDONLY` (bit 7, AP[2]), `PTE_UXN` (bit 54, *User eXecute Never*) y `PTE_PXN` (bit 53, *Privileged eXecute Never*); en x86_64 son R/W, U/S y NX. Una instrucción ejecutada desde una página con UXN/NX produce un fallo de permisos y el kernel envía `SIGSEGV`: **un código inyectado en un búfer de datos no se ejecuta** (política W^X). `PXN`/SMEP impiden que el kernel salte a código de usuario, y PAN/SMAP (`CONFIG_ARM64_PAN=y`, `CONFIG_ARM64_SW_TTBR0_PAN=y` en esta VM) impiden que el kernel lea o escriba memoria de usuario fuera de `copy_{to,from}_user`.
* **Papel en un mapa de archivo.** La inyección típica es cambiar una página de datos a ejecutable (`mprotect(PROT_EXEC)`) o escribir en una página de código del archivo. Las defensas son: `VM_MAYEXEC` ausente (el `mprotect` falla antes de tocar una PTE), COW (la escritura va a una copia anónima), `VM_MAYWRITE` ausente y la prohibición de `W+X` simultáneo (SELinux `execmem`, `MemoryDenyWriteExecute` de systemd).
* **En `mmguard`**: `PROT_EXEC` se rechaza (`mmap rechazado (PROT_EXEC prohibido)`) y `VM_MAYEXEC` se limpia: `mprotect(+EXEC)` devuelve `EACCES` (T03). En `smaps` el mapa muestra `VmFlags: rd mr ms io dc de dd`, **sin `ex` ni `me`** (T09). Eso garantiza que las PTE de la bóveda siempre llevan UXN.

---

## Parte II. Estrategia con apoyo de IA

### 3.1 Flujo de trabajo asistido por IA

El asistente (un LLM operando como agente de desarrollo con acceso a terminal en la VM) se usó **como consultor con verificación obligatoria**: ningún dato técnico, firma o nombre del kernel se aceptó sin contrastarlo con los headers, `kallsyms`, `Module.symvers` o una compilación real. El ciclo fue siempre el mismo: *pregunta acotada → respuesta → verificación mecánica → decisión → prueba*.

**Exploración arquitectónica.** Se usó la IA para (a) mapear en el material del profesor (`CapaKernel/paso4`, `paso6`) el patrón mínimo de un driver con `mmap` y `vm_operations_struct.fault`; (b) enumerar las alternativas de intercepción (tabla de syscalls, LSM, kprobes, eBPF, FUSE, `LD_PRELOAD`, módulo con dispositivo propio) y sus compensaciones; (c) listar los campos y banderas relevantes de `vm_area_struct`/`vm_flags`. Cada nombre propuesto se verificó con `grep` sobre los headers 6.8 y con `/proc/kallsyms`: de esa verificación salieron las correcciones de la sección 3.2 (el hook se llama `mmap_file`, no `file_mmap`; `vm_flags` ya no se asigna directamente; `sys_call_table` no es accesible).

**Generación y verificación de código C de bajo nivel.** La IA generó los borradores de los cinco archivos del módulo y de los programas de usuario; el control de calidad fue mecánico y no delegado: compilación contra los headers con `W=1` y `-Wall -Wextra` (cero advertencias), carga en una **VM desechable** (nunca en la Mac), lectura de `dmesg` tras cada prueba, y revisión de las decisiones delicadas (orden de bloqueos, `__GFP_ZERO`, qué pasa si falla una asignación, qué se libera y cuándo). Dos fallos de diseño reales se detectaron así y se corrigieron (sección 3.2, "hallazgos de la validación").

**Casos de prueba y PoC.** La IA escribió los PoC (`racer.c`: ataque tipo Dirty COW con tres hilos; `attacker.c`: elevación de permisos, `mprotect`, `fork`, `/proc/self/mem`; `stress.c`: concurrencia) y los scripts de prueba (Bash `run_tests.sh`, Python `kcore_check.py` y `remote_read_check.py`, `bpftrace` para detectar la firma del ataque). El principio fue *probar el ataque contra una referencia*: cada defensa tiene un **control** o una **ablación** que demuestra que el ataque es real: T06 (el mismo ataque contra un archivo normal), T13 (sin `VM_IO` el acceso remoto **sí** funciona), T07 (se altera a propósito el cifrado y el texto en claro y se verifica que se detecta).

### 3.2 Ingeniería de prompts y verificación crítica

**Tabla de prompts.** Los cinco prompts siguientes son los usados en los puntos de decisión. Cada uno fija rol, contexto, restricción y resultado esperado, y termina con el criterio de verificación que se aplicó a la respuesta.

| # | Rol | Contexto | Restricción | Resultado esperado | Verificación aplicada y resultado |
|---|---|---|---|---|---|
| 1 | "Consultor de seguridad de kernel Linux" | Parcial de SO: proteger archivos mapeados con `mmap` desde la capa de kernel. Kernel 6.8.0-147 aarch64, módulo cargable (no se puede recompilar el kernel). Material del profesor: `paso4` y `paso6`. | No tocar la tabla de syscalls ni CR0. Debe cargarse con `insmod` y descargarse sin reiniciar. | Tabla comparativa de 5 alternativas (syscall hook, LSM, kprobe, eBPF, dispositivo con `mmap` propio) con cobertura, riesgo y cómo denegar. | Se comprobó en la VM: `/sys/kernel/security/lsm` (sin `bpf`), `CONFIG_BPF_LSM=y`, `kallsyms_lookup_name` **no se exporta** (no enlaza), el hook se llama `mmap_file` y no `file_mmap`. Se descartó el LSM propio por no ser cargable en caliente y se eligió dispositivo + kprobe de observación. |
| 2 | "Revisor de código de kernel" | El `mmg_do_mmap()` de mmguard, pegado entero, más `include/linux/mm.h` de 6.8. | Para cada bandera de `vm_flags` que use, indicar el efecto exacto y el archivo/función del kernel que la lee. No inventar símbolos: si no se está seguro de que existe en 6.8, decirlo. | Justificación bandera por bandera de `VM_DONTCOPY/DONTEXPAND/DONTDUMP/IO/MAYWRITE/MAYEXEC` y detección de errores de API de versiones viejas. | Se contrastó con `mm.h` (valores `0x20000`, `0x40000`, `0x4000000`, `0x4000`), con `vm_flags_set/clear` (`mm.h:842/849`) y con la auditoría real (`flags_vma=0x4064099`). Se confirmó que `VM_IO` bloquea `/proc/pid/mem` y `process_vm_readv` (T09) y se descubrió que `O_RDONLY`+`MAP_SHARED` llega **sin** `VM_SHARED`. |
| 3 | "Ingeniero de criptografía aplicada en kernel" | La bóveda guarda páginas de 4 KiB cifradas en memoria del kernel; hay lectores concurrentes y sellados posteriores. | Usar la API `crypto_skcipher` y `crypto_shash` de 6.8. No reutilizar un par (clave, nonce). Verificar el MAC **antes** de descifrar. | Diseño AES-256-CTR con nonce por cifrado y HMAC-SHA256 (cifrar y luego autenticar), con el esqueleto de llamadas. | Se rechazó la API `crypto_alloc_ablkcipher` (no existe), se eligió `crypto_alloc_skcipher("ctr(aes)")` (existe: `Module.symvers`, `EXPORT_SYMBOL_GPL`); se verificó `crypto_wait_req`/`DECLARE_CRYPTO_WAIT`; se confirmó que el controlador real es `ctr-aes-ce` (`dmesg`: `boveda lista: 16 paginas cifradas con ctr-aes-ce`) y que el HMAC usa `sha256_ce` (visto en `ftrace`): aceleración por las extensiones criptográficas de la CPU. Prueba: T08 (entropía 7.950, 0 bloques repetidos). |
| 4 | "Atacante de memoria virtual" (red team) | El `racer.c` y el `attacker.c` debían reproducir Dirty COW y evasiones de permisos contra la bóveda. | Solo contra la VM propia. Debe incluir un **control** que demuestre que el ataque funciona donde corresponde. | Un PoC con tres hilos (`pwrite` a `/proc/self/mem`, `madvise(DONTNEED)`, lectura) y un control sobre un archivo normal. | T05 (0 de 11 555 318 escrituras), T06 (control: 2 141 809 escrituras sí cambian la copia privada, archivo intacto), T13 (ablación sin `VM_IO`). Se corrigió un aviso `-Wclobbered` por `longjmp` en el PoC. |
| 5 | "Auditor de concurrencia" | El `mmg_session_seal()` y el fallo de página comparten la sesión; un escritor sella y varios lectores refallan. | Señalar interbloqueos y lecturas inconsistentes. No proponer bloqueos que se tomen en orden contrario al de `mmap_lock`. | Lista de riesgos y un caso de estrés que los fuerce. | Se escribió `stress.c`. La primera versión de la prueba marcó lecturas inconsistentes; el análisis separó dos causas (ver "hallazgos") y llevó a cambiar el diseño a *copy-on-refresh*. Resultado final: `0` violaciones de integridad en 4 460 414 fallos. |

**Alucinaciones técnicas y APIs obsoletas detectadas.** Los modelos de lenguaje reproducen con frecuencia patrones de kernels antiguos. Para no discutirlo en abstracto, cada patrón se escribió como un "candidato" (`tools/alucinaciones/hNN_*.c`) y se **compiló contra los headers 6.8 de la VM** (`make halu`, salida completa en `evidencias/alucinaciones.txt`). Todos fallan, con el siguiente mensaje real del compilador:

| Candidato | Lo que propone el patrón antiguo | Resultado real en 6.8 | Qué se hizo en su lugar |
|---|---|---|---|
| h01 | `vma->vm_flags \|= VM_DONTEXPAND \| VM_DONTDUMP;` | `error: assignment of read-only member 'vm_flags'` (en 6.3 `vm_flags` pasó a `const`; `__vm_flags` es `__private`) | `vm_flags_set()`/`vm_flags_clear()` |
| h02 | `class_create(THIS_MODULE, "x")` | `error: too many arguments to function 'class_create'` (6.4 quitó el primer parámetro) | Se usa `misc_register()`, sin `class_create` |
| h03 | `kallsyms_lookup_name("sys_call_table")` para parchear syscalls | **No enlaza**: `ERROR: modpost: "kallsyms_lookup_name" [cand.ko] undefined!`. `sys_call_table` no está en `Module.symvers`; ni siquiera es parte de la ABI | Se descarta la tabla de syscalls; kprobe de solo observación |
| h04 | `write_cr0(read_cr0() & ~0x10000)` (apagar el bit WP para escribir en memoria de solo lectura) | `error: implicit declaration of function 'read_cr0'` y `'write_cr0'` en arm64. **Práctica insegura incluso donde existe** (x86): sin control de concurrencia, otro CPU escribe donde no debe mientras WP está apagado, y desde 5.3 el kernel fija el bit (*CR pinning*). *En x86 no se pudo probar en esta VM (aarch64); el dato de CR pinning es de la documentación del kernel* | No se modifica memoria protegida de ninguna forma |
| h05 | `get_user_pages(addr, 1, FOLL_WRITE, &pg, vmas)` (con `vmas`) | `error: too many arguments to function 'get_user_pages'` (6.5 eliminó `vmas`) | No se usa GUP en el módulo |
| h06 | `.fault = int fn(struct vm_area_struct *, struct vm_fault *)` | `error: initialization of 'vm_fault_t (*)(struct vm_fault *)' ... from incompatible pointer type` (firma vigente desde 4.11/4.17) | `vm_fault_t mmg_vm_fault(struct vm_fault *vmf)` |
| h07 | `crypto_alloc_ablkcipher("ctr(aes)",0,0)` (API asíncrona antigua) | `error: implicit declaration of function 'crypto_alloc_ablkcipher'` | `crypto_alloc_skcipher()` + `crypto_wait_req()` |
| h08 | `down_read(&current->mm->mmap_sem)` | `error: 'struct mm_struct' has no member named 'mmap_sem'` (5.8 la renombró a `mmap_lock`) | No se toma el bloqueo a mano: el kernel lo mantiene al llamar a `.fault`/`.mmap` |
| h09 | `__vmalloc(size, GFP_KERNEL, PAGE_KERNEL)` | `error: too many arguments to function '__vmalloc'` (5.8) | `alloc_page(GFP_KERNEL \| __GFP_ZERO)` |
| h10 | `proc_create("x", 0444, NULL, &file_operations)` | `error: passing argument 4 of 'proc_create' from incompatible pointer type` (5.6 exige `struct proc_ops`) | `proc_create_single()` con `seq_file` |
| h11 | `set_fs(KERNEL_DS)`/`mm_segment_t` | `error: unknown type name 'mm_segment_t'` (`set_fs` se eliminó entre 5.10 y 5.18 según la arquitectura) | Se usa solo `copy_{from,to}_user`/`memdup_user` |
| h12 | `.page_mkwrite = int fn(struct vm_area_struct *, struct vm_fault *)` | `error: ... incompatible pointer type` | `vm_fault_t mmg_vm_page_mkwrite(struct vm_fault *vmf)` |

Además, se verificó con `Module.symvers` que **no se pueden llamar desde un módulo** (no exportadas): `do_wp_page`, `follow_page`, `walk_page_range`, `security_mmap_file` (solo se alcanza con kprobe) y que `vm_flags_set` es una función `static inline` (no hay símbolo; se resuelve con el header). Son las funciones que una respuesta de IA "sugiere llamar" con frecuencia cuando se pide "interceptar el fallo de página" o "recorrer las PTE": no existen para un módulo.

**Hallazgos de la validación en tiempo de ejecución (errores que no eran de sintaxis).** El compilador no habría encontrado ninguno de los siguientes; salieron de las pruebas:

1. **Suposición falsa sobre el kernel**: se daba por hecho que un mapa `MAP_SHARED` de solo lectura conservaba `VM_SHARED`. La auditoría mostró `flags_vma=0x4064091` (sin `VM_SHARED`): el kernel lo quita si el descriptor no tiene `FMODE_WRITE`. Se ajustaron las pruebas para abrir con `O_RDWR` cuando se quiere ejercitar la regla propia del módulo, y se documentó en la pregunta 2.
2. **Interbloqueo de la propia infraestructura de pruebas**: el primer `run_tests.sh` colgaba porque `wait` sin argumentos espera también al proceso `tee` de la redirección; se corrigió esperando solo los PID de los hijos.
3. **Un falso positivo de mi propia verificación**: el grep para detectar errores del kernel (`BUG:`) coincidía con la cadena `DEBUG:` de mis mensajes de auditoría; se renombraron los mensajes.
4. **Riesgo real de lectura inconsistente (corregido).** `stress.c` (un escritor que sella y dos lectores que descartan su PTE) marcó lecturas con dos versiones distintas. El análisis encontró **dos causas distintas**: (a) *semántica normal de `mmap`*: dos accesos a la misma página pueden caer en dos fallos diferentes y ver dos versiones selladas distintas (la prueba se reformuló para exigir lo que sí es una invariante: ausencia de bloqueos, versión final uniforme y `0` fallos de integridad); (b) **un defecto de diseño real**: el refresco reescribía la página en claro *en sitio* y otro VMA de la misma sesión con la PTE viva podía ver una mezcla de dos versiones. Se cambió a **copy-on-refresh** (descifrar a una página nueva y publicar al terminar; la anterior se retira y se libera cuando nadie la tiene mapeada) y a descartar con `unmap_mapping_range` **solo el rango de las páginas selladas** (antes se descartaban todas las PTE de la bóveda). Tras el cambio, 4 460 414 fallos con `0` violaciones.
5. **Una práctica insegura que la IA propuso y que se evitó**: reutilizar el mismo nonce al volver a cifrar una página tras cada escritura (en CTR esto filtra el XOR de los textos en claro); se cambió por un contador global monótono que garantiza nonces únicos.

**Procedimiento de validación (contra los headers de la distribución).**

1. `grep` de cada símbolo, estructura o bandera en `/lib/modules/$(uname -r)/build/include` (campos de `struct vm_area_struct`, `vm_operations_struct`, `vm_fault`, `FOLL_*`, `VM_*`, `fault_flag`).
2. `Module.symvers` para saber si un símbolo se exporta y con qué licencia; `/proc/kallsyms` para saber si existe en el kernel en ejecución y si es global (`T`) o local (`t`).
3. Compilación del módulo con `make W=1` contra los headers 6.8 con el compilador exacto con el que se construyó el kernel (`aarch64-linux-gnu-gcc-13`): **0 advertencias**.
4. Carga **solo en la VM Lima desechable** (`insmod`), lectura de `dmesg`, `rmmod`, y revisión de que no aparezcan `Oops`, `BUG`, `WARNING`, `Call trace` ni `bad page`.
5. Pruebas funcionales y de ataque con ablaciones y controles (`tests/run_tests.sh`), pruebas de concurrencia (`stress`), y comparación con el comportamiento del kernel en un archivo normal.
6. Mediciones con `perf`, `strace`, `bpftrace` y `ftrace` (`trace-cmd`), con repeticiones.

### 3.3 Estrategia arquitectónica seleccionada

**Arquitectura.** Un módulo de kernel, `mmguard`, con cinco unidades (ver diagrama del `README.md`):

```
 proceso autorizado ──open/mmap/msync/ioctl──►  mmguard_main.c  (file_operations, ACL por UID)
                                                      │
        VMA endurecida (DONTCOPY|DONTEXPAND|DONTDUMP|IO, ¬MAYWRITE, ¬MAYEXEC)
                                                      ▼
 fallo de página ──► mmguard_vm.c: ¿mm ajeno? ¿UID revocado? ──► página PRIVADA de la sesión
                          │ crea/refresca/verifica SHA-256, repara si cambió
                          │ page_mkwrite → sucia ; msync/close → SELLA (re-cifra)
                          ▼
                  mmguard_vault.c: 16 páginas CIFRADAS (AES-256-CTR) + HMAC-SHA256 (+ nonce único)
                  mmguard_audit.c: dmesg + anillo + contadores (/proc/mmguard)
                  mmguard_kprobe.c: kprobe de observación sobre security_mmap_file
```

**Por qué esta combinación.** (1) El **dispositivo con `mmap` propio** permite controlar la VMA y cada fallo de página, que es lo único que ve el acceso por puntero. (2) El **cifrado + MAC** hace que el almacenamiento en la memoria del kernel sea inútil para quien lo lea. (3) El **kprobe** da la cobertura de auditoría sobre mapeos ajenos sin riesgo. (4) Se descartaron: el parche a la tabla de syscalls (inseguro, no viable), el LSM propio (no cargable en caliente y la VM no tiene BPF-LSM activo), y la protección en espacio de usuario (`LD_PRELOAD`/FUSE, eludible: ver Parte III).

**Matriz de compensaciones: rendimiento frente a seguridad** (medidos en la VM; ver tabla completa y método en la Parte III):

| Mecanismo | Qué protege | Costo medido | Cobertura / límite |
|---|---|---|---|
| Validación de ACL en `mmap` | Quién puede mapear | Sobrecosto de `mmap`+`munmap`: tabla de la Parte III | Solo la VMA creada; se repite en el fallo |
| Validación de ACL en **cada fallo** | Revocación inmediata | Una búsqueda protegida por *spinlock* por fallo (inferior a 1 µs) | Cubre mapas ya existentes |
| `VM_IO`, `VM_DONTCOPY`, `VM_MAYWRITE` limpio | Acceso remoto, herencia, Dirty COW | Ninguno medible en tiempo de ejecución (son bits) | `VM_IO` impide `ptrace`/`/proc/pid/mem`: **también** a depuradores legítimos |
| Descifrado por página en el fallo | Texto en claro solo para el dueño | Fallo "frío": decenas de µs por 16 páginas (tabla Parte III) | El texto en claro está en RAM mientras el proceso lo usa |
| SHA-256 de la página en cada fallo (`verify_on_fault`) | Detecta alteración del marco físico (Dirty COW u otro) | Es el costo dominante del fallo "caliente" (tabla Parte III); se puede apagar en caliente | Solo se ve al volver a fallar la página, no en cada acceso |
| Sellado (AES + MAC) en `msync`/`close` | Integridad y confidencialidad de lo escrito | Una operación de cifrado de 4 KiB por página sucia | Sin sellado, los cambios no persisten (es intencional) |
| Auditoría (`dmesg` + anillo + contadores) | Trazabilidad | `printk` limitado con ratelimit en rutas calientes; contadores atómicos | El anillo conserva los últimos 128 eventos |
| kprobe sobre `security_mmap_file` | Visibilidad de mapas de archivos vigilados | Un `d_path` por `mmap` de archivo del sistema, solo si hay `watch_path` | Observa, **no puede denegar** |

La regla de decisión fue: **todo lo que es una bandera es gratis y siempre se activa; lo que cuesta CPU por fallo (cifrado, SHA-256) se justifica por la propiedad que da y, si no se necesita, se configura** (`verify_on_fault=0`).

---

## Parte III. Implementación, presentación y argumentación

### 4.1 Entregables de código e implementación

**Estructura (todo en `~/Projects/so-parcial3`, ver `README.md`).**

| Archivo | Líneas | Responsabilidad |
|---|---:|---|
| `include/mmguard_uapi.h` | 73 | Estructuras e `ioctl` compartidos entre el módulo y los programas de usuario |
| `kernel/mmguard_main.c` | 288 | Dispositivo `/dev/mmguard` (`miscdevice`), `file_operations`, ACL por UID, `ioctl`, parámetros del módulo |
| `kernel/mmguard_vm.c` | 504 | `mmap` con validación y endurecimiento de la VMA, `vm_operations_struct` (`fault`, `page_mkwrite`, `open`, `close`), sesiones, sellado |
| `kernel/mmguard_vault.c` | 370 | Bóveda: AES-256-CTR (`crypto_skcipher`), HMAC-SHA256 y SHA-256 (`crypto_shash`), nonces |
| `kernel/mmguard_audit.c` | 170 | Auditoría: `dmesg`, anillo de eventos y contadores, `/proc/mmguard` |
| `kernel/mmguard_kprobe.c` | 87 | `kprobe` de observación sobre `security_mmap_file` (opcional, por parámetro) |
| `kernel/mmguard.h`, `kernel/Makefile` | 168 | Definiciones internas y Kbuild (`W=1`) |
| `user/*.c` | 793 | `client` (cliente autorizado), `attacker` (ataques), `racer` (carrera Dirty COW), `stress`, `mmgctl` (administración), `bench`, y la demostración de `LD_PRELOAD` |
| `tests/` | 378 | `run_tests.sh` (Bash), `kcore_check.py`, `remote_read_check.py` (Python), `detector_ebpf.sh` (bpftrace) |

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

**Demostración de las pruebas (resultado real de `sudo ./tests/run_tests.sh` en la VM, `evidencias/run_tests.log`): 52 casos PASAN, 0 FALLAN.** Extractos:

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
=== T05 ===  [INFO] vault: 0 pwrite(/proc/self/mem) exitosos, 11555318 fallidos, 18251342 madvise(DONTNEED), 1433329 lecturas, 0 veces el mapa mostro contenido distinto, 0 senales
             [OK] dirtycow-vault: escrituras exitosas=0, desviaciones del contenido=0, sesion nueva ve el original=si
=== T06 ===  [INFO] control: 2141809 pwrite(/proc/self/mem) exitosos, 0 fallidos, 11802974 madvise(DONTNEED), 4252546 lecturas, 828293 veces el mapa mostro contenido distinto, 0 senales
             [OK] dirtycow-control: archivo normal: el mapa privado cambio 828 293 veces (COW legitimo) pero el ARCHIVO sigue intacto=si
=== T07 ===  [OK] integ-session: tras refallar: contenido restaurado=si, violaciones +1, reparadas +1
             [OK] integ-vault: VERIFY reporta 1 pagina(s) corrupta(s); lector nuevo -> SIGBUS; violaciones +2
=== T08 ===  [OK] kcore-coincide: los 4096 bytes en kaddr=0x... leidos de /proc/kcore coinciden con el cifrado del modulo
             [OK] kcore-entropia: entropia de Shannon = 7.950 bits/byte (texto en claro ~ 0.2; maximo 8)
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

**Método.** Se midió en la VM Lima (aarch64, 4 CPU, 4 GiB, kernel 6.8.0-147; ver `evidencias/mediciones/entorno.txt`), con `user/bench` (microbenchmarks propios con `clock_gettime` y `getrusage`), `perf stat`, `strace -T/-c`, `bpftrace` (kprobe/kretprobe) y `ftrace` (`trace-cmd record -p function_graph`). Cada microbenchmark se repitió **7 veces**; se informa la **mediana** y el **mínimo** (el mínimo es la mejor estimación del costo sin interferencia de la máquina anfitriona, que es una Mac compartida con otras tareas: en ejecuciones anteriores, con el anfitrión ocupado, las medianas se multiplicaron por 1.7 a 3 respecto de esta, por lo que **las razones son más confiables que los valores absolutos**). Todas las salidas crudas están en `evidencias/mediciones/`. Cada iteración trabaja sobre 16 páginas (64 KiB). Los casos comparados son el archivo normal (en la *page cache*, sin la defensa) y `/dev/mmguard` (con la defensa).

**Tabla resumen** (`evidencias/mediciones/resumen.md`):

| Operación | mediana ns/iter | mín. ns/iter | fallos/iter | ns por fallo |
|---|---:|---:|---:|---:|
| `pread()` de 64 KiB (sin mmap), page cache caliente | 1647 | 1629 | 0.00 | n/a |
| `mmap`+`munmap` de 16 páginas, archivo normal | 831 | 811 | 0.00 | n/a |
| `mmap`+`munmap` de 16 páginas, /dev/mmguard | 1479 | 1457 | 0.00 | n/a |
| mmap + tocar 16 págs + munmap, archivo normal | 2405 | 2317 | 1.00 | 2405 |
| open + mmap + tocar 16 págs + munmap + close, mmguard (sesión nueva: descifra 16 págs) | 68180 | 67238 | 16.00 | 4261 |
| ídem, con verify_on_fault=0 | 68568 | 67079 | 16.00 | 4286 |
| MADV_DONTNEED + tocar 16 págs, archivo normal (refallo, páginas en page cache) | 1811 | 1676 | 1.00 | 1811 |
| MADV_DONTNEED + tocar 16 págs, mmguard (refallo; verifica SHA-256 de cada página) | 32923 | 31560 | 16.00 | 2058 |
| ídem, con verify_on_fault=0 | 8352 | 8043 | 16.00 | 522 |

Lectura de la tabla:

* **`mmap`+`munmap`** (sin tocar páginas): archivo normal **831 ns**, `mmguard` **1479 ns**. El costo extra de la defensa en la llamada es de **648 ns** por `mmap`+`munmap` (validación de ACL, rango y banderas, y auditoría con `pr_info` + anillo). Es independiente del tamaño del mapa.
* **Fallo de página "caliente"** (la página en claro ya existe; se descarta la PTE y se vuelve a tocar): archivo normal **1811 ns** para las 16 páginas con **1 solo fallo** (*fault-around* mapea 16 páginas de una vez desde la caché), `mmguard` **32923 ns** con **16 fallos**: **2058 ns por fallo** con la verificación SHA-256 de cada página y **522 ns por fallo** sin ella (`verify_on_fault=0`). La verificación de integridad en claro es entonces el **75 %** del costo de un fallo caliente.
* **Fallo "frío"** (sesión nueva: se descifran las 16 páginas, con MAC, AES-256-CTR y SHA-256, más `open`/`close`): **68180 ns** por iteración, **4261 ns por página**, frente a **2405 ns** del archivo normal (1 fallo). Es el precio del descifrado: se paga **una vez por página y por sesión**, no por acceso.
* **`pread()` de 64 KiB** (sin `mmap`): **1647 ns**: copiar 64 KiB con `read` cuesta del mismo orden que tocar las 16 páginas del archivo normal por `mmap`; la ventaja del `mmap` (sin copia, sin cambio de contexto por acceso) se conserva en `mmguard` una vez descifradas las páginas: los accesos posteriores al fallo corren a velocidad de hardware.

**`perf stat`** (`evidencias/mediciones/perf_stat.txt`): en el caso caliente, el archivo normal produce **50 052** fallos para 50 000 iteraciones y `mmguard` **800 066** (16 por iteración; los fallos que se contabilizan son los de **hardware**, de ahí que la defensa no reduzca la tasa de fallos: la aumenta de 1 a 16 por iteración porque cada página se atiende por separado y no hay *fault-around*, algo necesario para descifrar y autenticar página a página). `task-clock`: **161.61 ms** frente a **2261.69 ms**; los cambios de contexto son despreciables (`9`) en ambos casos.

**`strace`** (`evidencias/mediciones/strace_T.txt`): `strace -T` mide cada `mmap` de 64 KiB con resolución de 1 µs y suma el costo de `ptrace` a ambos casos: archivo normal mediana **22.0 µs**, `/dev/mmguard` mediana **24.0 µs**; la diferencia entre ambos queda dentro del ruido del propio `strace`, por lo que **no sirve para aislar el sobrecosto de `mmap`** (para eso se usó el microbenchmark). `strace -c` confirma que el tiempo de `bench warm dev` se va en `madvise` (el descarte de la PTE), no en llamadas del módulo: el trabajo de la defensa ocurre en el manejador de fallos, que `strace` no ve.

**`bpftrace`** (`evidencias/mediciones/bpftrace.txt`, latencia por fallo medida con `kprobe`/`kretprobe`):

| Qué se mide | Promedio por llamada | Llamadas | Observación |
|---|---:|---:|---|
| `handle_mm_fault`, archivo normal (caliente) | **725 ns** | 20 054 | 1 llamada por iteración (mapea 16 páginas) |
| `handle_mm_fault`, `mmguard` (caliente) | **1063 ns** | 640 085 | 2.0 llamadas por cada fallo atendido por el módulo (ver abajo) |
| Solo el callback `mmg_vm_fault`, caliente, **con** SHA-256 | **1848 ns** | 320 016 | casi todo el costo del fallo es nuestro callback |
| Solo `mmg_vm_fault`, caliente, **sin** SHA-256 | **400 ns** | 320 016 | el costo base de ACL, bloqueo y auditoría |
| Solo `mmg_vm_fault`, frío (sesión nueva, descifra) | **3829 ns** | 48 000 | MAC + AES-CTR + SHA-256 de 4 KiB, más reservar la página |

*Observación derivada de las cuentas:* `handle_mm_fault` se invoca **dos veces por cada fallo** que llega a `mmg_vm_fault` (columna "Llamadas"), mientras que para el archivo normal es una. El histograma de `handle_mm_fault` es bimodal (una moda de 128 a 256 ns y otra de 1 a 2 µs). La explicación coherente con esos datos es que el primer intento corre con el bloqueo por VMA (6.4+), no puede completar un `.fault` de un driver que no declara ese soporte y devuelve `VM_FAULT_RETRY`; el segundo corre con `mmap_lock` y hace el trabajo. *(Es una inferencia a partir de las mediciones; no se verificó leyendo `mm/memory.c`, cuyas fuentes no están en esta VM.)* Es un costo impuesto por el kernel a cualquier `vm_ops` de driver, ajeno a la defensa.

**`ftrace`** (`evidencias/mediciones/ftrace_mmg_vm_fault.txt`) muestra el desglose de una invocación fría de `mmg_vm_fault()`: `mmg_policy_lookup` (ACL), `mutex_lock`, `alloc_pages`, `mmg_vault_read_page` → `vault_check_locked` → `vault_mac` → `hmac_*`/`sha256_ce_*` (el MAC), `vault_crypt` → `ctr-aes-ce` (el descifrado) y `mmg_digest` (el SHA-256 de la página en claro). Las duraciones con `function_graph` están infladas por la instrumentación; sirve para ver **cuál es la distribución del trabajo**, no para el valor absoluto.

**Conclusiones de la medición.** (1) `mmap` cuesta aproximadamente **1.8** veces más que el de un archivo normal, en el orden de **microsegundos**; irrelevante salvo en cargas que mapean y desmapean sin parar. (2) El costo real está en el fallo de página: descifrar es un costo de **una sola vez por página y por sesión** (decenas de µs por 16 páginas), y el fallo posterior de una página ya descifrada cuesta **18 veces** el de un archivo normal por página mapeada si se verifica el SHA-256, y **5** sin verificarlo. (3) Una vez instalada la PTE, el acceso no cuesta nada más: es memoria normal. (4) `verify_on_fault` es el control de **rendimiento frente a seguridad**: se puede apagar en caliente (`echo 0 > /sys/module/mmguard/parameters/verify_on_fault`) cuando se acepta no detectar la alteración del marco físico en claro.

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
