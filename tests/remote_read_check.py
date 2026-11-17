#!/usr/bin/env python3
"""
remote_read_check.py: un administrador (root) intenta leer, desde FUERA, el texto en claro que
un proceso autorizado tiene mapeado. Con VM_IO (y sin vm_ops->access) get_user_pages rechaza la VMA,
así que /proc/<pid>/mem y process_vm_readv fallan. Además se muestran los VmFlags de la VMA.

Uso (root):  remote_read_check.py <usuario-autorizado>
"""
import ctypes
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.environ.get("MMG_BIN", os.path.join(HERE, "..", "user"))
CLIENT = os.path.join(BIN, "client")


class IoVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def main():
    usuario = sys.argv[1] if len(sys.argv) > 1 else "mmreader"
    fallos = 0
    p = subprocess.Popen(["sudo", "-u", usuario, CLIENT, "hold", "4"], stdout=subprocess.PIPE, text=True)
    linea = p.stdout.readline().split()
    addr, pid = int(linea[1], 16), int(linea[2])

    def check(nombre, cond, detalle):
        nonlocal fallos
        print("[%s] %s: %s" % ("OK" if cond else "FALLA", nombre, detalle))
        if not cond:
            fallos += 1

    ablacion = os.environ.get("MMG_ABLATION") == "1"   # módulo cargado con use_vm_io=0

    # 1) /proc/<pid>/mem
    try:
        with open("/proc/%d/mem" % pid, "rb", buffering=0) as f:
            f.seek(addr)
            data = f.read(32)
        if ablacion:
            check("ablacion-proc-mem", bool(data), "SIN VM_IO root SI leyo %r (por eso VM_IO es una capa necesaria)" % data)
        else:
            check("remoto-proc-mem", not data, "root leyo %r de /proc/%d/mem" % (data, pid))
    except OSError as e:
        check("ablacion-proc-mem" if ablacion else "remoto-proc-mem", not ablacion,
              "root no puede leer /proc/%d/mem en 0x%x: %s" % (pid, addr, e.strerror))

    # 2) process_vm_readv
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.process_vm_readv.restype = ctypes.c_ssize_t
    buf = ctypes.create_string_buffer(32)
    local = IoVec(ctypes.cast(buf, ctypes.c_void_p), 32)
    remote = IoVec(addr, 32)
    n = libc.process_vm_readv(pid, ctypes.byref(local), 1, ctypes.byref(remote), 1, 0)
    err = os.strerror(ctypes.get_errno()) if n < 0 else ""
    if ablacion:
        check("ablacion-process_vm_readv", n > 0, "SIN VM_IO process_vm_readv -> %s" % (err or "leyo %d bytes: %r" % (n, buf.raw[:n])))
    else:
        check("remoto-process_vm_readv", n < 0, "process_vm_readv -> %s" % (err or "leyo %d bytes: %r" % (n, buf.raw[:n])))

    # 3) VmFlags de la VMA
    flags = ""
    objetivo = "%x-" % addr
    leyendo = False
    with open("/proc/%d/smaps" % pid) as f:
        for ln in f:
            if ln.startswith(objetivo):
                leyendo = True
            elif leyendo and ln.startswith("VmFlags:"):
                flags = ln.split(":", 1)[1].split()
                break
    esperados = {"dc", "de", "dd"} if ablacion else {"io", "dc", "de", "dd"}
    prohibidos = {"ex", "wr", "mw", "me"}
    check("vmflags", esperados <= set(flags) and not (prohibidos & set(flags)),
          "VmFlags=%s  (io=VM_IO dc=DONTCOPY de=DONTEXPAND dd=DONTDUMP; sin wr/ex/mw/me)" % " ".join(flags))
    p.wait()
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
