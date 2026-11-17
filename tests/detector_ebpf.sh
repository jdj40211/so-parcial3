#!/usr/bin/env bash
# detector_ebpf.sh: ejemplo de la pregunta 7. Un programa bpftrace (eBPF sobre kprobes/tracepoints, SIN recompilar
# el kernel) detecta la firma del ataque Dirty COW mientras corre racer: ráfagas de madvise(MADV_DONTNEED)
# junto con escrituras a /proc/<pid>/mem del MISMO proceso.
#   sudo tests/detector_ebpf.sh <ruta-a-racer> <usuario>
set -u
RACER=${1:?ruta a racer}; USR=${2:-mmreader}
OUT=$(mktemp)
bpftrace -e '
tracepoint:syscalls:sys_enter_madvise /args->behavior == 4/ { @madv_dontneed[comm, pid] = count(); }
kprobe:mem_rw /arg4 == 1/ { @procmem_write[comm, pid] = count(); }
interval:s:4 { exit(); }
END { printf("---\n"); }' > "$OUT" 2>&1 &
BPF=$!
sleep 2
sudo -u "$USR" "$RACER" vault 1 "TOP-SECRET mmguard:" > /dev/null 2>&1
wait $BPF
cat "$OUT" | grep -E "racer|---" | sed 's/^/    /'
M=$(grep -E "^@madv_dontneed\[racer" "$OUT" | sed 's/.*: *//' | head -1)
W=$(grep -E "^@procmem_write\[racer" "$OUT" | sed 's/.*: *//' | head -1)
rm -f "$OUT"
if [ "${M:-0}" -gt 10000 ] && [ "${W:-0}" -gt 10000 ]; then
	echo "[OK] ebpf-detector: firma de Dirty COW detectada sin tocar el kernel: madvise(DONTNEED)=$M y escrituras a /proc/pid/mem=$W en 1 s"
else
	echo "[FALLA] ebpf-detector: no se vio la firma (madvise=${M:-0}, mem_write=${W:-0})"
fi
