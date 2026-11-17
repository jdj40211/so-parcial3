#!/usr/bin/env bash
# verificar.sh: contrasta contra los headers del kernel en ejecución cada "candidato" (código que un
# asistente de IA tiende a proponer a partir de APIs de kernels antiguos) y registra el resultado REAL del
# compilador. Además comprueba qué símbolos están exportados (Module.symvers y /proc/kallsyms).
# Uso:  ./verificar.sh        (en la VM; deja la salida en stdout)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
KDIR=/lib/modules/$(uname -r)/build
TMP=$(mktemp -d /tmp/halu.XXXXXX)
KCC=$(ls /usr/bin/$(uname -m)-linux-gnu-gcc-13 2>/dev/null | head -1)
echo "kernel: $(uname -r) ($(uname -m))   headers: $KDIR"
echo
for f in "$HERE"/h*.c; do
	n=$(basename "$f" .c)
	d="$TMP/$n"; mkdir -p "$d"; cp "$f" "$d/cand.c"; echo 'obj-m := cand.o' > "$d/Makefile"
	echo "### $n"
	sed -n '2p' "$f"
	if make -C "$KDIR" M="$d" ${KCC:+CC=$KCC} modules > "$d/log" 2>&1; then
		echo "RESULTADO: compila (sin error)"
	else
		echo "RESULTADO: NO compila / NO enlaza"
	fi
	grep -E "error:|ERROR: modpost|warning: implicit|undefined" "$d/log" | sed "s#$d/##" | head -4
	echo
done
echo "### Exportación de símbolos (Module.symvers del 6.8)"
SYMVERS="$KDIR/Module.symvers"
for s in kallsyms_lookup_name sys_call_table security_mmap_file handle_mm_fault do_wp_page follow_page \
         unmap_mapping_range remap_pfn_range vmf_insert_pfn vm_insert_page crypto_alloc_skcipher \
         crypto_skcipher_encrypt crypto_alloc_shash register_kprobe walk_page_range zap_vma_ptes \
         apply_to_page_range vm_flags_set misc_register; do
	l=$(awk -v s="$s" '$2==s {print $3, $4}' "$SYMVERS" | head -1)
	k=$(sudo awk -v s="$s" '$3==s {print $2; exit}' /proc/kallsyms 2>/dev/null)
	printf '%-26s exportado: %-28s kallsyms: %s\n' "$s" "${l:-NO}" "${k:--}"
done
rm -rf "$TMP"
