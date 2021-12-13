### ELF manipulation tools ###

```self_parser``` - parse a 32bit ELF file and output its contents
```sinject```     - inject a payload (from shell.h) in the target executable
                    and redirect entry point execution. First the payload is
                    executed then, the old program flow.
```target_shellcode``` - the ELF that we want to modify
```shellcode```   - the built shellcode from assembly
