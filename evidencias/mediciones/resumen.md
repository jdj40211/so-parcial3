| Operación | mediana ns/iter | mín. ns/iter | fallos/iter | ns por fallo |
|---|---:|---:|---:|---:|
| `pread()` de 64 KiB (sin mmap), page cache caliente | 1647 | 1629 | 0.00 | n/a |
| `mmap`+`munmap` de 16 páginas, archivo normal | 831 | 811 | 0.00 | n/a |
| `mmap`+`munmap` de 16 páginas, /dev/mmguard | 1479 | 1457 | 0.00 | n/a |
| mmap + tocar 16 págs + munmap, archivo normal | 2405 | 2317 | 1.00 | 2405 |
| open + mmap + tocar 16 págs + munmap + close, mmguard (sesión nueva: descifra 16 págs) | 68180 | 67238 | 16.00 | 4261 |
| ídem, con verify_on_fault=0 | 68568 | 67079 | 16.00 | 4286 |
| MADV_DONTNEED + tocar 16 págs, archivo normal (refallo, páginas en page cache) | 1811 | 1676 | 1.00 | 1811 |
| MADV_DONTNEED + tocar 16 págs, mmguard (refallo; verifica SHA-256 de cada página) | 32923 | 31560 | 16.00 | 2058 |
| ídem, con verify_on_fault=0 | 8352 | 8043 | 16.00 | 522 |
