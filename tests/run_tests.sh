#!/usr/bin/env bash
# run_tests.sh: corre TODAS las pruebas de mmguard en la VM y termina con un resumen PASA/FALLA.
#
#   sudo ./tests/run_tests.sh            carga el módulo, prueba, descarga
#
# Requisitos: haber compilado antes (make en la raíz del repositorio), ser root.
# Crea los usuarios de prueba mmreader (lector), mmwriter (escritor) y mmintruso (sin permisos).
# Deja la salida cruda en evidencias/run_tests.log, dmesg.log y proc_mmguard.txt.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVID="${EVID:-$ROOT/evidencias}"
STAGE=/opt/mmguard-test          # ruta accesible a todos los usuarios (el home suele ser 750)
KO="$ROOT/kernel/mmguard.ko"
WATCH=/tmp/mmguard_vigilado
export MMG_BIN="$STAGE"

[ "$(id -u)" = 0 ] || { echo "ejecutar con sudo"; exit 1; }
[ -f "$KO" ] && [ -x "$ROOT/user/client" ] || { echo "falta compilar: make -C $ROOT"; exit 1; }
mkdir -p "$EVID" && exec > >(tee "$EVID/run_tests.log") 2>&1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "[PASA]  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "[FALLA] $1"; }
seccion() { echo; echo "=== $1 ==="; }

# Ejecuta un comando de prueba; cada línea [OK]/[FALLA] que imprima cuenta como un caso.
run() {
	local out rc l
	out="$("$@" 2>&1)"; rc=$?
	echo "$out" | sed 's/^/    /'
	local nok nfail
	nok=$(echo "$out" | grep -c '^\[OK\]'); nfail=$(echo "$out" | grep -c '^\[FALLA\]')
	PASS=$((PASS+nok)); FAIL=$((FAIL+nfail))
	if [ "$nok" = 0 ] && [ "$nfail" = 0 ]; then
		[ $rc = 0 ] && ok "$*" || bad "$* (sin veredicto, rc=$rc)"
	fi
}
as() { local u=$1; shift; sudo -u "$u" "$@"; }

load_module() {   # $@ = parámetros del módulo
	rmmod mmguard 2>/dev/null
	insmod "$KO" allow_debug=1 watch_path=$WATCH "$@" || { echo "insmod fallo"; exit 1; }
	"$STAGE/mmgctl" add "$(id -u mmreader)" r  >/dev/null
	"$STAGE/mmgctl" add "$(id -u mmwriter)" rw >/dev/null
	"$STAGE/mmgctl" add 0 r >/dev/null
}

seccion "Preparación"
for u in mmreader mmwriter mmintruso; do id "$u" >/dev/null 2>&1 || useradd -m -s /bin/bash "$u"; done
rm -rf "$STAGE"; install -d -m 755 "$STAGE"
install -m 755 "$ROOT"/user/{client,attacker,mmgctl,racer,bench,stress,ldp_victim,ldp_victim_static,ldp_guard.so} "$STAGE/"
echo "kernel: $(uname -r)  arch: $(uname -m)  fecha: $(date -Is)"
dmesg --clear
load_module
modinfo -F vermagic "$KO"
echo "usuarios: mmreader=$(id -u mmreader) mmwriter=$(id -u mmwriter) mmintruso=$(id -u mmintruso)"
cat /proc/mmguard | head -3

seccion "T01 Acceso autorizado lee el contenido descifrado"
out=$(as mmreader "$STAGE/client" read 0 90); echo "    mmreader lee: $out"
echo "$out" | grep -q "TOP-SECRET mmguard:" && ok "autorizado (mmreader, lectura) ve el texto en claro" || bad "autorizado no ve el texto"
out=$(as mmreader "$STAGE/client" read 5 60 --private); echo "    mmreader (MAP_PRIVATE) pagina 5: $out"
echo "$out" | grep -q "PAGINA-05" && ok "lectura con MAP_PRIVATE de otra pagina" || bad "lectura MAP_PRIVATE"

seccion "T02 Usuario no autorizado rechazado"
run as mmintruso "$STAGE/attacker" unauth
out=$(as mmintruso "$STAGE/client" read 0 90 2>&1); echo "    mmintruso: $out"

seccion "T03 Intentos de subir permisos y evadir el mapeo"
for t in mprotect shared-write private-write exec fork mremap procmem; do
	run as mmreader "$STAGE/attacker" "$t"
done

seccion "T04 Escritura controlada y sellado (msync)"
as mmwriter "$STAGE/client" write 2 "DATO NUEVO del escritor autorizado" | sed 's/^/    /'
out=$(as mmreader "$STAGE/client" read 2 60); echo "    mmreader ve: $out"
echo "$out" | grep -q "DATO NUEVO" && ok "el lector ve la version sellada por el escritor" || bad "el lector no ve el cambio"
st=$("$STAGE/mmgctl" stats); echo "    $st"
echo "$st" | grep -q "seals=[1-9]" && echo "$st" | grep -q "mkwrite=[1-9]" && ok "page_mkwrite y sellado contabilizados" || bad "contadores de escritura"
python3 - <<PY
import re,sys
t=open("/proc/mmguard").read()
sys.exit(0 if re.search(r"ESCRIBE .*marcada sucia", t) and re.search(r"SELLA .*re-cifradas", t) else 1)
PY
[ $? = 0 ] && ok "auditoria registra ESCRIBE y SELLA en /proc/mmguard" || bad "auditoria de escritura"

seccion "T05 Carrera estilo Dirty COW (madvise DONTNEED + /proc/self/mem), 5 s"
run as mmreader "$STAGE/racer" vault 5 "TOP-SECRET mmguard:"
echo "    $("$STAGE/mmgctl" stats)"
seccion "T06 Control: la misma carrera contra un archivo normal"
head -c 200 /dev/urandom | base64 -w0 | sed 's/^/ARCHIVO-ORIGINAL-ESTABLE /' > /tmp/mmguard_control.txt; chmod 644 /tmp/mmguard_control.txt
run as mmreader "$STAGE/racer" file /tmp/mmguard_control.txt 5 "ARCHIVO-ORIGINAL-ESTABLE"

seccion "T06b Concurrencia: 1 escritor sellando + 2 lectores refallando (4 s)"
rm -f /tmp/mmguard_stress_*.out; PIDS=""; n=0
for who in "mmwriter writer" "mmreader reader" "mmreader reader"; do
	set -- $who; n=$((n+1)); as "$1" "$STAGE/stress" "$2" 4 > "/tmp/mmguard_stress_$n.out" 2>&1 &
	PIDS="$PIDS $!"
done
wait $PIDS        # (no usar "wait" a secas: esperaría también al proceso tee de la redirección)
run bash -c 'cat /tmp/mmguard_stress_*.out'
FINALV=$(sed -n 's/^FINAL //p' /tmp/mmguard_stress_*.out | head -1); rm -f /tmp/mmguard_stress_*.out
run "$STAGE/stress" check "$FINALV"
[ "$("$STAGE/mmgctl" stats | sed 's/.*integrity_fail=\([0-9]*\).*/\1/')" = 0 ] && ok "sin violaciones de integridad tras la concurrencia" || bad "violaciones de integridad en la concurrencia"
echo "    $("$STAGE/mmgctl" stats)"

seccion "T07 Integridad: modificación indebida detectada"
run "$STAGE/attacker" integ-session
run "$STAGE/attacker" integ-vault
"$STAGE/mmgctl" verify | sed 's/^/    /' && ok "tras reprovisionar, VERIFY reporta la boveda sana" || bad "VERIFY despues de reprovisionar"

seccion "T08 El contenido en la memoria del kernel está cifrado (lectura de /proc/kcore)"
run python3 "$ROOT/tests/kcore_check.py"
seccion "T09 Root no puede leer el texto en claro desde fuera (VM_IO)"
run python3 "$ROOT/tests/remote_read_check.py" mmreader

seccion "T10 Revocación de UID en la ACL surte efecto en el siguiente fallo"
as mmreader "$STAGE/attacker" after-revoke 2 > /tmp/mmguard_revoke.out 2>&1 &
BG=$!; sleep 1; "$STAGE/mmgctl" del "$(id -u mmreader)" | sed 's/^/    /'; wait $BG
run cat /tmp/mmguard_revoke.out
"$STAGE/mmgctl" add "$(id -u mmreader)" r >/dev/null

seccion "T11 Auditoría con kprobe sobre security_mmap_file (ruta vigilada $WATCH*)"
echo "contenido vigilado" > ${WATCH}_datos.txt; chmod 644 ${WATCH}_datos.txt
before=$("$STAGE/mmgctl" stats | sed 's/.*probe_mmap=//')
as mmreader python3 -c "
import mmap; f=open('${WATCH}_datos.txt','rb'); m=mmap.mmap(f.fileno(),0,prot=mmap.PROT_READ); print('    mmap normal de archivo vigilado:', m[:10])"
after=$("$STAGE/mmgctl" stats | sed 's/.*probe_mmap=//')
echo "    probe_mmap: $before -> $after"
[ "$after" -gt "$before" ] && grep -q "KPROBE .*mmap de archivo vigilado" /proc/mmguard && ok "el kprobe auditó el mmap del archivo vigilado" || bad "kprobe"

seccion "T12 Auditoría: dmesg y /proc/mmguard"
cp /proc/mmguard "$EVID/proc_mmguard.txt"
dmesg > "$EVID/dmesg.log"
for ev in MMAP FALLO DENIEGA ESCRIBE SELLA INTEGRIDAD KPROBE ADMIN; do
	n=$(grep -c "mmguard: $ev pid=[0-9]* tgid=[0-9]* uid=[0-9]* comm=" "$EVID/dmesg.log")
	[ "$n" -gt 0 ] && ok "dmesg tiene eventos $ev con pid/uid/comm ($n lineas)" || bad "dmesg sin eventos $ev"
done
grep -E "DENIEGA|INTEGRIDAD" "$EVID/dmesg.log" | head -6 | sed 's/^/    /'
echo "    $("$STAGE/mmgctl" stats)"

seccion "T12b Detección con eBPF (bpftrace) de la firma del ataque, sin recompilar el kernel"
run "$ROOT/tests/detector_ebpf.sh" "$STAGE/racer" mmreader

seccion "T12c Por qué en el kernel: la defensa en espacio de usuario (LD_PRELOAD) se elude, la del kernel no"
echo "dato confidencial del archivo protegido" > /tmp/mmguard_protegido.txt; chmod 644 /tmp/mmguard_protegido.txt
L="$STAGE/ldp_guard.so"
o1=$(as mmintruso env LD_PRELOAD=$L "$STAGE/ldp_victim" libc /tmp/mmguard_protegido.txt); echo "    LD_PRELOAD + mmap() de libc        : $o1"
o2=$(as mmintruso env LD_PRELOAD=$L "$STAGE/ldp_victim" raw  /tmp/mmguard_protegido.txt); echo "    LD_PRELOAD + syscall directa       : $o2"
o3=$(as mmintruso env LD_PRELOAD=$L "$STAGE/ldp_victim_static" libc /tmp/mmguard_protegido.txt); echo "    LD_PRELOAD + binario estatico      : $o3"
o4=$(as mmintruso "$STAGE/ldp_victim" raw /dev/mmguard); echo "    mmguard (kernel) + syscall directa : $o4"
o5=$(as mmintruso "$STAGE/ldp_victim_static" raw /dev/mmguard); echo "    mmguard (kernel) + binario estatico: $o5"
echo "$o1" | grep -q BLOQUEADO && echo "$o2" | grep -q ACCEDIO && echo "$o3" | grep -q ACCEDIO && ok "la biblioteca LD_PRELOAD solo frena el camino por libc: la syscall directa y el binario estatico la eluden" || bad "demostracion LD_PRELOAD"
echo "$o4" | grep -q BLOQUEADO && echo "$o5" | grep -q BLOQUEADO && ok "el kernel (ACL de mmguard) bloquea a mmintruso incluso con syscall directa y binario estatico" || bad "kernel no bloqueo la syscall directa"

seccion "T13 Ablación: sin VM_IO (use_vm_io=0) la defensa de VM_MAYWRITE sigue resistiendo la carrera"
load_module use_vm_io=0
run as mmreader "$STAGE/racer" vault 4 "TOP-SECRET mmguard:"
MMG_ABLATION=1 run python3 "$ROOT/tests/remote_read_check.py" mmreader

seccion "T14 Higiene del módulo: descarga limpia y dmesg sin errores del kernel"
rmmod mmguard && ok "rmmod limpio (sin referencias colgadas)" || bad "rmmod"
dmesg >> "$EVID/dmesg.log"; dmesg > "$EVID/dmesg_final.log"
if grep -E "Oops|BUG:|WARNING:|Call trace|Call Trace|bad page|kernel panic|general protection|Unable to handle" "$EVID/dmesg_final.log"; then
	bad "dmesg contiene mensajes de error del kernel"
else
	ok "dmesg sin Oops, BUG, WARNING ni bad page"
fi
grep -q "mmguard: descargado" "$EVID/dmesg_final.log" && ok "mensaje de descarga registrado" || bad "sin mensaje de descarga"
[ ! -e /dev/mmguard ] && [ ! -e /proc/mmguard ] && ok "/dev/mmguard y /proc/mmguard eliminados" || bad "restos del dispositivo"

echo
echo "================================================================"
echo "RESUMEN: $PASS casos PASAN, $FAIL casos FALLAN"
if [ "$FAIL" = 0 ]; then echo "RESULTADO FINAL: PASA"; else echo "RESULTADO FINAL: FALLA"; fi
echo "================================================================"
chown -R "${SUDO_USER:-root}" "$EVID" 2>/dev/null
[ "$FAIL" = 0 ]
