# Makefile del módulo mmguard (Kbuild).  Uso:  make   |   make W=1   |   make clean
obj-m := mmguard.o
mmguard-y := mmguard_main.o mmguard_vm.o mmguard_vault.o mmguard_audit.o mmguard_kprobe.o

# La cabecera compartida con el espacio de usuario vive en ../include
ccflags-y += -I$(src)/../include -Wall -Wextra -Wno-unused-parameter

KDIR ?= /lib/modules/$(shell uname -r)/build

# Si existe el compilador con el nombre exacto con que se construyó el kernel de la
# distribución (aarch64-linux-gnu-gcc-13), se usa: evita el aviso "the compiler differs".
KCC := $(firstword $(wildcard /usr/bin/$(shell uname -m)-linux-gnu-gcc-13))
ifneq ($(KCC),)
KCCARG := CC=$(KCC)
endif

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) W=1 $(KCCARG) modules

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean

.PHONY: all clean
