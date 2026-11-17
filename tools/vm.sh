#!/usr/bin/env bash
# Atajo para desarrollo desde la Mac: sincroniza el repo a la VM y ejecuta un comando allá.
#   tools/vm.sh 'cd ~/so-parcial3 && make && sudo ./tests/run_tests.sh'
set -euo pipefail
"$(dirname "$0")/sync_vm.sh"
limactl shell sokernel bash -c "$1"
