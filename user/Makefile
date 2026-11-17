# Programas de usuario de mmguard.  Uso: make   |   make clean
CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -g -pthread -I../include
BINS     = client attacker mmgctl racer bench stress ldp_victim ldp_victim_static ldp_guard.so

all: $(BINS)

ldp_victim_static: ldp_victim.c
	$(CC) $(CFLAGS) -static -o $@ $<

ldp_guard.so: ldp_guard.c
	$(CC) $(CFLAGS) -shared -fPIC -o $@ $< -ldl

%: %.c mmg_util.h ../include/mmguard_uapi.h
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BINS)

.PHONY: all clean
