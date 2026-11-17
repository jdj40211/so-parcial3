#!/usr/bin/env bash
# medir.sh: mediciones de la sección 4.2 (sobrecosto de mmap y de fallos de página).
# Debe ejecutarse como root dentro de la VM, con el repositorio compilado:  sudo ./tools/medir.sh
# Deja todo en evidencias/mediciones/ (salidas crudas) y evidencias/mediciones/resumen.md (tabla).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/evidencias/mediciones"; mkdir -p "$OUT"
B="$ROOT/user/bench"
KO="$ROOT/kernel/mmguard.ko"
REPS=${REPS:-7}
FILE=$(mktemp /tmp/mm_bench.XXXXXX)
[ "$(id -u)" = 0 ] || { echo "ejecutar con sudo"; exit 1; }

head -c 65536 /dev/urandom > $FILE        # 16 páginas, en la page cache tras la primera lectura
cat $FILE > /dev/null
rmmod mmguard 2>/dev/null; insmod "$KO" && "$ROOT/user/mmgctl" add 0 r >/dev/null
{
  echo "# $(date -Is)  kernel $(uname -r) $(uname -m)  CPUs=$(nproc)  repeticiones=$REPS"
  echo "# CPU: $(lscpu | grep -E 'Vendor ID|Model name|Model:|Thread|Core|BogoMIPS' | sed 's/  */ /g' | tr '\n' ';')"
} | tee "$OUT/entorno.txt"

bench() {   # etiqueta, comando...
  local tag=$1; shift
  for i in $(seq 1 "$REPS"); do echo "$tag $("$@")"; done >> "$OUT/bench_crudo.txt"
}
: > "$OUT/bench_crudo.txt"
echo "== microbenchmarks (con defensa completa: cifrado + MAC + SHA-256 por fallo)"
bench "A:completa" $B read $FILE 100000
bench "A:completa" $B mmap file $FILE 50000
bench "A:completa" $B mmap dev 50000
bench "A:completa" $B cold file $FILE 20000
bench "A:completa" $B cold dev 20000
bench "A:completa" $B warm file $FILE 50000
bench "A:completa" $B warm dev 50000
echo "== ablación: verify_on_fault=0 (sin SHA-256 por fallo; el cifrado y el MAC siguen)"
echo 0 > /sys/module/mmguard/parameters/verify_on_fault
bench "B:sin_verify" $B cold dev 20000
bench "B:sin_verify" $B warm dev 50000
echo 1 > /sys/module/mmguard/parameters/verify_on_fault

echo "== perf stat (warm: 50000 iteraciones x 16 páginas)"
for t in "file $FILE" "dev"; do
  { echo "### perf stat bench warm $t"; perf stat -e page-faults,minor-faults,task-clock,context-switches,cpu-migrations \
      $B warm $t 50000 2>&1; echo; } >> "$OUT/perf_stat.txt"
done
{ echo "### perf stat bench mmap (solo la llamada mmap+munmap)"; for t in "file $FILE" "dev"; do
    echo "--- $t"; perf stat -e task-clock,page-faults $B mmap $t 50000 2>&1; done; } >> "$OUT/perf_stat.txt"

echo "== strace -T (duración de cada mmap) y strace -c"
: > "$OUT/strace_T.txt"
for t in "file $FILE" "dev"; do
  echo "### strace -T bench mmap $t" >> "$OUT/strace_T.txt"
  strace -T -e trace=mmap,munmap -o "$OUT/.s.txt" $B mmap $t 3000 >/dev/null 2>&1
  grep -E "mmap\(NULL, 65536" "$OUT/.s.txt" | head -2000 | awk -F'<' '{gsub(/>/,"",$NF); print $NF}' > "$OUT/.t.txt"
  python3 - "$OUT/.t.txt" "$t" >> "$OUT/strace_T.txt" <<'PY'
import sys, statistics
v=[float(x)*1e6 for x in open(sys.argv[1]).read().split()]
print("%s: %d llamadas mmap(64 KiB), mediana=%.1f us, media=%.1f us, p95=%.1f us (incluye el sobrecosto de ptrace, igual para ambos)" % (sys.argv[2], len(v), statistics.median(v), statistics.mean(v), sorted(v)[int(len(v)*.95)]))
PY
done
{ echo; echo "### strace -c bench warm dev 2000"; strace -c -f $B warm dev 2000 2>&1 >/dev/null | head -14; } >> "$OUT/strace_T.txt"
rm -f "$OUT"/.s.txt "$OUT"/.t.txt

echo "== bpftrace: latencia de handle_mm_fault y del callback mmg_vm_fault"
bt() {  # descripción, programa, comando
  { echo "### $1"; bpftrace -e "$2" -c "$3" 2>&1 | grep -v "^Attaching"; echo; } >> "$OUT/bpftrace.txt"
}
: > "$OUT/bpftrace.txt"
PROG='kprobe:handle_mm_fault /comm=="bench"/ { @s[tid]=nsecs } kretprobe:handle_mm_fault /@s[tid]/ { @ns=hist(nsecs-@s[tid]); @avg=avg(nsecs-@s[tid]); @n=count(); delete(@s[tid]) }'
bt "handle_mm_fault total, archivo normal (warm, 20000 it.)" "$PROG" "$B warm file $FILE 20000"
bt "handle_mm_fault total, mmguard (warm, 20000 it.)" "$PROG" "$B warm dev 20000"
PROG2='kprobe:mmg_vm_fault { @s[tid]=nsecs } kretprobe:mmg_vm_fault /@s[tid]/ { @ns=hist(nsecs-@s[tid]); @avg=avg(nsecs-@s[tid]); @n=count(); delete(@s[tid]) }'
bt "solo el callback mmg_vm_fault (warm, con SHA-256), 20000 it." "$PROG2" "$B warm dev 20000"
echo 0 > /sys/module/mmguard/parameters/verify_on_fault
bt "solo el callback mmg_vm_fault (warm, SIN SHA-256), 20000 it." "$PROG2" "$B warm dev 20000"
echo 1 > /sys/module/mmguard/parameters/verify_on_fault
bt "solo el callback mmg_vm_fault (cold: sesion nueva, descifra), 3000 it." "$PROG2" "$B cold dev 3000"

echo "== ftrace (trace-cmd, function_graph) del callback de fallo, una sola pasada"
trace-cmd record -q -p function_graph -g mmg_vm_fault -o "$OUT/.trace.dat" $B cold dev 2 >/dev/null 2>&1
trace-cmd report -i "$OUT/.trace.dat" 2>/dev/null | grep -E "^ *bench" > "$OUT/.rep.txt"
python3 - "$OUT/.rep.txt" > "$OUT/ftrace_mmg_vm_fault.txt" <<'PY'
import re, sys
# Extrae la PRIMERA invocación completa de mmg_vm_fault (la de la primera página de la sesión).
lines = open(sys.argv[1]).read().splitlines()
cap, depth = [], None
for ln in lines:
    body = ln.split("|", 1)[1] if "|" in ln else ""
    if depth is None:
        if re.search(r"mmg_vm_fault\(\) \{", body):
            depth = len(body) - len(body.lstrip())
            cap.append(ln)
        continue
    cap.append(ln)
    if body.strip() == "}" and len(body) - len(body.lstrip()) == depth:
        break
print("# Primera invocación de mmg_vm_fault (function_graph; tiempos en us; instrumentar infla las duraciones)")
for ln in cap:
    print(re.sub(r"^\s*bench-\d+\s+\[\d+\]\s+[\d.]+:\s+funcgraph_(entry|exit):\s*", "", ln))
PY
rm -f "$OUT/.rep.txt"
rm -f "$OUT/.trace.dat" "$OUT/.trace.dat".*
wc -l "$OUT/ftrace_mmg_vm_fault.txt"

python3 "$ROOT/tools/resumir_mediciones.py" "$OUT" | tee "$OUT/resumen.md"
rmmod mmguard
rm -f $FILE
chown -R "${SUDO_USER:-root}" "$OUT" 2>/dev/null
