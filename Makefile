# Makefile raíz de mmguard.
#   make            compila el módulo de kernel y los programas de usuario (sin advertencias)
#   make load       carga el módulo (sudo)        make unload   lo descarga
#   make test       corre todas las pruebas (sudo, carga/descarga el módulo solo)
#   make bench      corre las mediciones de la sección 4.2 (sudo)
#   make       compila los "candidatos alucinados" y registra los errores reales
#   make clean
KDIR ?= /lib/modules/$(shell uname -r)/build

all: modules user

modules:
	$(MAKE) -C kernel KDIR=$(KDIR)

user:
	$(MAKE) -C user

load: modules
	sudo insmod kernel/mmguard.ko allow_debug=1

unload:
	sudo rmmod mmguard

test: all
	sudo ./tests/run_tests.sh

bench: all
	sudo ./tools/medir.sh

clean:
	$(MAKE) -C kernel clean KDIR=$(KDIR)
	$(MAKE) -C user clean

.PHONY: all modules user load unload test bench clean
