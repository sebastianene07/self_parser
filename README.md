### ELF manipulation tools ###

```self_parser``` - parse a 32bit ELF file and output its contents
```sinject```     - inject a payload (from shell.h) in the target executable
                    and redirect entry point execution. First the payload is
                    executed then, the old program flow.
```target_shellcode``` - the ELF that we want to modify
```shellcode```   - the built shellcode from assembly

### Debug the ELF code after injection ###

```
gdb target_shellcode
starti
```

In another window verify where is the program loaded in memory and print out
the memory mappings:

```
cat /proc/$(pidof target_shellcode)/maps
56555000-56556000 r--p 00000000 08:05 16256395                           /home/sebastianene/repos/self_parser/target_shellcode
56556000-56557000 r-xp 00001000 08:05 16256395                           /home/sebastianene/repos/self_parser/target_shellcode
56557000-56558000 r--p 00002000 08:05 16256395                           /home/sebastianene/repos/self_parser/target_shellcode
56558000-5655a000 rw-p 00002000 08:05 16256395                           /home/sebastianene/repos/self_parser/target_shellcode
f7fcb000-f7fcf000 r--p 00000000 00:00 0                                  [vvar]                    
...

```

Back in the GDB client window set a breakpoint in:

```
b *(0x56555000 + new_entry_point)
c
```
