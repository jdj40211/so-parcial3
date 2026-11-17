#!/usr/bin/env python3
"""Resume bench_crudo.txt (mediana y mínimo de las repeticiones) en una tabla Markdown."""
import re
import statistics
import sys
from collections import defaultdict

out = sys.argv[1]
datos = defaultdict(list)
for ln in open(out + "/bench_crudo.txt"):
    m = re.match(r"(\S+) RESULT modo=(\S+) iteraciones=(\d+) ns_por_iter=(\d+) fallos_por_iter=([\d.]+)", ln)
    if m:
        datos[(m.group(1), m.group(2))].append((float(m.group(4)), float(m.group(5))))

filas = [
    ("A:completa", "read-archivo", "`pread()` de 64 KiB (sin mmap), page cache caliente"),
    ("A:completa", "mmap-archivo", "`mmap`+`munmap` de 16 páginas, archivo normal"),
    ("A:completa", "mmap-mmguard", "`mmap`+`munmap` de 16 páginas, /dev/mmguard"),
    ("A:completa", "cold-archivo", "mmap + tocar 16 págs + munmap, archivo normal"),
    ("A:completa", "cold-mmguard", "open + mmap + tocar 16 págs + munmap + close, mmguard (sesión nueva: descifra 16 págs)"),
    ("B:sin_verify", "cold-mmguard", "ídem, con verify_on_fault=0"),
    ("A:completa", "warm-archivo", "MADV_DONTNEED + tocar 16 págs, archivo normal (refallo, páginas en page cache)"),
    ("A:completa", "warm-mmguard", "MADV_DONTNEED + tocar 16 págs, mmguard (refallo; verifica SHA-256 de cada página)"),
    ("B:sin_verify", "warm-mmguard", "ídem, con verify_on_fault=0"),
]
print("| Operación | mediana ns/iter | mín. ns/iter | fallos/iter | ns por fallo |")
print("|---|---:|---:|---:|---:|")
for conf, modo, desc in filas:
    v = datos.get((conf, modo))
    if not v:
        continue
    ns = [a for a, _ in v]
    f = v[0][1]
    por_fallo = ("%.0f" % (statistics.median(ns) / f)) if f else "n/a"
    print("| %s | %.0f | %.0f | %.2f | %s |" % (desc, statistics.median(ns), min(ns), f, por_fallo))
