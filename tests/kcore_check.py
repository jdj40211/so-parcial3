#!/usr/bin/env python3
"""
kcore_check.py: demuestra que el contenido de la bóveda, EN LA MEMORIA DEL KERNEL, está cifrado.

Método (requiere root y el módulo cargado con allow_debug=1):
  1. mmgctl dumpct N devuelve la dirección virtual del kernel (kaddr) de la página cifrada
     y una copia del contenido que entrega el propio módulo.
  2. Se lee la MISMA dirección directamente desde /proc/kcore (la imagen de la memoria del
     kernel), sin pasar por el módulo: es lo que vería un atacante con lectura de memoria.
  3. Se comprueba: coinciden; no contienen el texto secreto; la entropía es alta; no hay
     bloques repetidos (un modo ECB o la ausencia de cifrado los delataría: el texto en claro
     tiene ~4000 bytes en cero).
"""
import math
import os
import struct
import subprocess
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("MMG_BIN", os.path.join(HERE, "..", "user"))
MMGCTL = os.path.join(BIN, "mmgctl")
CLIENT = os.path.join(BIN, "client")
SECRETO = b"TOP-SECRET"
FRAGMENTOS = [b"lanzamiento", b"EAFIT", b"boveda", b"7-4-1-9"]


def dumpct(page):
    out = subprocess.run([MMGCTL, "dumpct", str(page)], capture_output=True, text=True, check=True).stdout.split("\n")
    kaddr = int(out[0].split("kaddr=")[1].split()[0], 16)
    data = bytes.fromhex("".join(out[1:]).replace(" ", ""))
    return kaddr, data


def read_kcore(kaddr, n):
    with open("/proc/kcore", "rb") as f:
        hdr = f.read(64)
        phoff, = struct.unpack_from("<Q", hdr, 32)
        phentsize, phnum = struct.unpack_from("<HH", hdr, 54)
        for i in range(phnum):
            f.seek(phoff + i * phentsize)
            p_type, _flags, p_offset, p_vaddr, _pa, p_filesz, _ms, _al = struct.unpack("<IIQQQQQQ", f.read(56))
            if p_type == 1 and p_vaddr <= kaddr and kaddr + n <= p_vaddr + p_filesz:
                f.seek(p_offset + (kaddr - p_vaddr))
                return f.read(n)
    raise RuntimeError("la direccion 0x%x no esta en ningun PT_LOAD de /proc/kcore" % kaddr)


def entropia(b):
    c = Counter(b)
    return -sum(v / len(b) * math.log2(v / len(b)) for v in c.values())


def bloques_repetidos(b):
    blocks = [b[i:i + 16] for i in range(0, len(b), 16)]
    return len(blocks) - len(set(blocks))


def main():
    if os.geteuid() != 0:
        print("[FALLA] kcore: ejecutar como root")
        return 1
    fallos = 0

    def check(nombre, cond, detalle):
        nonlocal fallos
        print("[%s] %s: %s" % ("OK" if cond else "FALLA", nombre, detalle))
        if not cond:
            fallos += 1

    kaddr, dump = dumpct(0)
    kc = read_kcore(kaddr, 4096)
    check("kcore-coincide", kc == dump, "los 4096 bytes en kaddr=0x%x leidos de /proc/kcore coinciden con el cifrado del modulo" % kaddr)
    check("kcore-sin-secreto", SECRETO not in kc and not any(f in kc for f in FRAGMENTOS),
          "ni 'TOP-SECRET' ni fragmentos del texto aparecen en la memoria del kernel")
    h = entropia(kc)
    check("kcore-entropia", h > 7.9, "entropia de Shannon = %.3f bits/byte (texto en claro ~ 0.2; maximo 8)" % h)
    rep = bloques_repetidos(kc)
    check("kcore-sin-patrones", rep == 0, "bloques de 16 bytes repetidos: %d (el texto en claro tiene ~250 bloques en cero)" % rep)

    claro = subprocess.run([CLIENT, "read", "0", "60"], capture_output=True, text=True).stdout.strip()
    check("claro-solo-en-el-proceso", SECRETO in claro.encode() and claro.encode() not in kc,
          "el proceso autorizado ve: %r" % claro[:40])
    print("[INFO] primeros 32 bytes cifrados en kaddr: %s" % kc[:32].hex())
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
