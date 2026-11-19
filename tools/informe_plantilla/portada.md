# Parcial 3 de Sistemas Operativos: seguridad de archivos mapeados con `mmap()` desde la capa de kernel

**Universidad EAFIT** · Escuela de Ciencias Aplicadas e Ingeniería · Departamento de Informática y Analítica  
**Asignatura:** Sistemas Operativos, periodo 2026-2  
**Evaluación:** Parcial práctico-teórico (valor 25 %)  
**Integrantes:** Juan David Sierra (GitHub `jdj40211`) y Andrés Prieto  
**Fecha:** 17 de noviembre de 2026  
**Código:** https://github.com/jdj40211/so-parcial3 (módulo de kernel `mmguard`, programas de usuario, pruebas, mediciones y evidencias)  
**Entorno de pruebas:** VM Lima `sokernel`, Ubuntu 24.04 aarch64, kernel `6.8.0-147-generic`

> Nota de método. Todas las cifras de este informe salen de archivos de `evidencias/` generados por las pruebas y mediciones reales en la VM
> (`tools/build_informe.py` rellena las cifras desde esos archivos). Los nombres de estructuras, banderas y funciones del kernel se contrastaron con los
> headers de 6.8, con `/proc/kallsyms` y con `Module.symvers`. Lo que no se logró o no se probó está dicho explícitamente en cada parte.

## Resumen ejecutivo

* **Qué se construyó.** `mmguard`: un módulo de kernel (5 archivos C, `W=1` sin advertencias) que expone `/dev/mmguard`, una bóveda de 16 páginas **cifradas en la memoria del kernel** (AES-256-CTR + HMAC-SHA256). El texto en claro solo se crea, página por página, en el manejador de fallos y solo para procesos autorizados por una ACL de UID, en páginas privadas de cada sesión. La VMA se endurece (`VM_MAYWRITE`/`VM_MAYEXEC` limpios, `VM_DONTCOPY|VM_DONTEXPAND|VM_DONTDUMP|VM_IO`), las escrituras pasan por `page_mkwrite` y se **sellan** (re-cifran) con `msync`, y todo queda auditado.
* **Resultado de las pruebas.** `run_tests.sh`: **{{N_PASS}} casos PASAN, {{N_FAIL}} FALLAN**, con descarga limpia y `dmesg` sin errores del kernel. Incluye: UID no autorizado rechazado, `mprotect`/`MAP_SHARED|PROT_WRITE`/`PROT_EXEC` rechazados, ataque de carrera tipo Dirty COW resistido (0 escrituras exitosas de {{T05_ATT}} intentos), modificación indebida detectada y reparada, contenido de la memoria del kernel verificado **cifrado** por `/proc/kcore`, y `LD_PRELOAD` eludido mientras el kernel no.
* **Costo medido.** `mmap`+`munmap` ≈ {{M_MMAP_DEV}} ns (archivo normal {{M_MMAP_FILE}} ns); fallo "caliente" ≈ {{M_WARM_DEV_PF}} ns por página ({{M_WARM_NOV_PF}} ns sin la verificación SHA-256); descifrado "frío" ≈ {{M_COLD_DEV_PF}} ns por página, una vez por página y por sesión. Después del fallo, el acceso es memoria normal.
* **Límites.** Probado solo en aarch64 / 6.8.0-147; el texto en claro está en RAM mientras se usa; el `kprobe` solo audita; un administrador es de confianza. Ver "Limitaciones y trabajo futuro".

**Contenido:** Parte I (10 preguntas) · Parte II (estrategia con IA: 3.1, 3.2, 3.3) · Parte III (implementación, resultados, mediciones, argumentación, limitaciones).

---
