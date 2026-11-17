#!/usr/bin/env bash
# Copia el repositorio de la Mac (solo lectura en la VM) a ~/so-parcial3 dentro de la VM Lima.
# Los artefactos de compilación de la VM se conservan (están excluidos, por lo que --delete no los borra).
set -euo pipefail
SRC="${SRC:-$HOME/Projects/so-parcial3}"
limactl shell sokernel bash -c "mkdir -p ~/so-parcial3 && rsync -a --delete \
  --exclude .git --exclude evidencias \
  --exclude '*.o' --exclude '*.ko' --exclude '*.mod' --exclude '*.mod.c' --exclude '.*.cmd' \
  --exclude Module.symvers --exclude modules.order --exclude '.tmp_versions' \
  --exclude /user/client --exclude /user/attacker --exclude /user/mmgctl --exclude /user/racer --exclude /user/bench --exclude /user/stress --exclude /user/ldp_victim --exclude /user/ldp_victim_static --exclude /user/ldp_guard.so \
  $SRC/ ~/so-parcial3/"
