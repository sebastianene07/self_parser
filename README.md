### ELF manipulation tools ###

Currently support X86/64.

```self_parser``` - parse a 32bit ELF file and output its contents
```sinject```     - inject a payload (from shell.h) in the target executable
                    and redirect entry point execution. First the payload is
                    executed then, the old program flow.
```target```    - the ELF that we want to modify
```payload```   - the ELF payload that we want to inject


### Building ###

Assuming `mdm` package is installed on your system build with Make:
```
make -j`ncpus`
```

### Example output ###

```
seb@fulg:~/repos/self_parser$ ./sinject 
Press CTRL-C or q to stop, for help press ? or type help

>> select_target target
[*] Found 64-bit target ELF
[*] Found max payload size: 3747

>> select_payload payload

>> inject_fini
[*] Payload .text size 94
[*] Payload entrypoint 0x102b
[*] Append at 0x115d
[*] Old target entrypoint at 0x1050
[*] New entrypoint at 0x1188
[*] Patch nop-chain with call at 11b4
>> q

```

### Explanation for advanced users ###

`sinject` opens and mmaps the specified payload and the target file. It finds the RE(read+execute) PT_LOAD
segment in the target and it computes the remaining space to the next page boundary. That will be the max size
of our payload. It then copies the .text section from the payload at the end of the .fini section from the target,
it updates the entrypoint in the target to point to the payload first and then it patches the nop-chain from
the payload to perform a jump to the original entrypoint.

Note: The payload has to have the nop-chain which will be used by sinject to patch a call instruction to the
original entrypoint from the target.

