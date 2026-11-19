#!/usr/bin/env python3
"""
build_informe.py: genera docs/INFORME.md a partir de la plantilla (tools/informe_plantilla/) y de las
EVIDENCIAS reales (evidencias/): cada cifra del informe sale de un archivo de evidencias, no se escribe a mano.
Uso:  python3 tools/build_informe.py
"""
import os
import re
import statistics
import subprocess
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EV = os.path.join(ROOT, "evidencias")
TPL = os.path.join(ROOT, "tools", "informe_plantilla")


def rd(path):
    return open(path, encoding="utf-8").read()


def fmt(n):
    return "{:,}".format(int(n)).replace(",", " ")


def nlines(path):
    return sum(1 for _ in open(path, encoding="utf-8", errors="replace"))


V = {}
log = rd(os.path.join(EV, "run_tests.log"))

m = re.search(r"RESUMEN: (\d+) casos PASAN, (\d+) casos FALLAN", log)
V["N_PASS"], V["N_FAIL"] = m.group(1), m.group(2)


def seccion(titulo):
    i = log.index("=== " + titulo)
    j = log.index("\n=== ", i + 5)
    return log[i:j]


t05 = seccion("T05")
m = re.search(r"\[INFO\] vault: (.*)", t05)
V["T05_LINE"] = m.group(1)
V["T05_ATT"] = fmt(re.search(r"0 pwrite\(/proc/self/mem\) exitosos, (\d+) fallidos", t05).group(1))
t06 = seccion("T06 ")
V["T06_LINE"] = re.search(r"\[INFO\] control: (.*)", t06).group(1)
mm = re.search(r"control: (\d+) pwrite\(/proc/self/mem\) exitosos, 0 fallidos, (\d+) madvise\(DONTNEED\).*?(\d+) veces el mapa", t06)
V["T06_W"], V["T06_MADV"], V["T06_MISM"] = fmt(mm.group(1)), fmt(mm.group(2)), fmt(mm.group(3))
t13 = seccion("T13")
V["T13_ATT"] = fmt(re.search(r"0 pwrite\(/proc/self/mem\) exitosos, (\d+) fallidos", t13).group(1))
t12b = seccion("T12b")
V["DET_M"] = fmt(re.search(r"madvise\(DONTNEED\)=(\d+)", t12b).group(1))
V["DET_W"] = fmt(re.search(r"mem=(\d+) en 1 s", t12b).group(1))
t06b = seccion("T06b")
V["STRESS_F"] = fmt(re.search(r"faults=(\d+)", t06b).group(1))
t08 = seccion("T08")
V["ENTROPY"] = re.search(r"Shannon = ([\d.]+)", t08).group(1)

# ---- mediciones
datos = defaultdict(list)
for ln in rd(os.path.join(EV, "mediciones", "bench_crudo.txt")).splitlines():
    m = re.match(r"(\S+) RESULT modo=(\S+) iteraciones=(\d+) ns_por_iter=(\d+) fallos_por_iter=([\d.]+)", ln)
    if m:
        datos[(m.group(1), m.group(2))].append(float(m.group(4)))
med = lambda k: statistics.median(datos[k])
V["REPS"] = str(len(datos[("A:completa", "read-archivo")]))
A = "A:completa"
mmap_f, mmap_d = med((A, "mmap-archivo")), med((A, "mmap-mmguard"))
warm_f, warm_d = med((A, "warm-archivo")), med((A, "warm-mmguard"))
warm_n = med(("B:sin_verify", "warm-mmguard"))
cold_d, cold_f = med((A, "cold-mmguard")), med((A, "cold-archivo"))
V.update({
    "M_MMAP_FILE": "%.0f" % mmap_f, "M_MMAP_DEV": "%.0f" % mmap_d, "D_MMAP": "%.0f" % (mmap_d - mmap_f),
    "R_MMAP": "%.1f" % (mmap_d / mmap_f),
    "M_WARM_FILE": "%.0f" % warm_f, "M_WARM_DEV": "%.0f" % warm_d,
    "M_WARM_DEV_PF": "%.0f" % (warm_d / 16), "M_WARM_NOV_PF": "%.0f" % (warm_n / 16),
    "PCT_SHA": "%.0f" % ((warm_d - warm_n) / warm_d * 100),
    "R_WARM": "%.0f" % (warm_d / warm_f), "R_WARM_NOV": "%.0f" % (warm_n / warm_f),
    "M_COLD_DEV": "%.0f" % cold_d, "M_COLD_DEV_PF": "%.0f" % (cold_d / 16), "M_COLD_FILE": "%.0f" % cold_f,
    "M_READ": "%.0f" % med((A, "read-archivo")),
})
V["R_WARM"] = V["R_WARM"] + "×"
V["R_WARM_NOV"] = V["R_WARM_NOV"] + "×"
V["R_MMAP"] = V["R_MMAP"] + "×"
V["R_WARM"] = V["R_WARM"].replace("×", "")
V["R_WARM_NOV"] = V["R_WARM_NOV"].replace("×", "")
V["R_MMAP"] = V["R_MMAP"].replace("×", "")

V["TABLA_BENCH"] = rd(os.path.join(EV, "mediciones", "resumen.md")).strip()

perf = rd(os.path.join(EV, "mediciones", "perf_stat.txt"))
pf = re.findall(r"([\d,.]+)\s+page-faults", perf)
tc = re.findall(r"([\d,.]+) msec task-clock", perf)
cs = re.findall(r"([\d,.]+)\s+context-switches", perf)
V["PF_FILE"], V["PF_DEV"] = fmt(pf[0].replace(",", "")), fmt(pf[1].replace(",", ""))
V["TC_FILE"], V["TC_DEV"], V["CS_DEV"] = tc[0], tc[1], cs[1]

st = rd(os.path.join(EV, "mediciones", "strace_T.txt"))
meds = re.findall(r"mediana=([\d.]+) us", st)
V["ST_FILE"], V["ST_DEV"] = meds[0], meds[1]

bt = rd(os.path.join(EV, "mediciones", "bpftrace.txt"))
bloques = re.split(r"### ", bt)[1:]
avg = lambda b: (re.search(r"@avg: (\d+)", b).group(1), re.search(r"@n: (\d+)", b).group(1))
keys = ["BT_FILE", "BT_DEV", "BT_VM_SHA", "BT_VM_NOSHA", "BT_VM_COLD"]
for k, b in zip(keys, bloques):
    a, n = avg(b)
    V[k], V[k + "_N"] = a, fmt(n)
V["BT_RATIO"] = "%.1f" % (int(V["BT_DEV_N"].replace(" ", "")) / int(V["BT_VM_SHA_N"].replace(" ", "")))

# ---- tamaños de archivos
def total(paths):
    return sum(nlines(os.path.join(ROOT, p)) for p in paths)

import glob
V["L_UAPI"] = str(nlines(os.path.join(ROOT, "include/mmguard_uapi.h")))
for k, f in (("L_MAIN", "mmguard_main.c"), ("L_VM", "mmguard_vm.c"), ("L_VAULT", "mmguard_vault.c"),
             ("L_AUDIT", "mmguard_audit.c"), ("L_KPROBE", "mmguard_kprobe.c")):
    V[k] = str(nlines(os.path.join(ROOT, "kernel", f)))
V["L_H"] = str(nlines(os.path.join(ROOT, "kernel/mmguard.h")) + nlines(os.path.join(ROOT, "kernel/Makefile")))
V["L_USER"] = str(sum(nlines(f) for f in glob.glob(os.path.join(ROOT, "user", "*.c"))))
V["L_TESTS"] = str(sum(nlines(f) for f in glob.glob(os.path.join(ROOT, "tests", "*")) if os.path.isfile(f)))

portada = rd(os.path.join(TPL, "portada.md"))
cuerpo = portada + "\n" + rd(os.path.join(TPL, "parte3.md"))
faltan = set(re.findall(r"\{\{(\w+)\}\}", cuerpo)) - set(V)
if faltan:
    raise SystemExit("placeholders sin valor: %s" % sorted(faltan))
for k, v in V.items():
    cuerpo = cuerpo.replace("{{%s}}" % k, v)
open(os.path.join(ROOT, "docs", "INFORME.md"), "w", encoding="utf-8").write(cuerpo)
print("docs/INFORME.md generado (%d lineas)" % cuerpo.count("\n"))
