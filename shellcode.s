.section .text
_start:
push   %ebp
mov    %esp,%ebp

push   %ebx
push   %ecx

movl   $0x66206563,-0x14(%ebp)
movl   $0x696361,-0x10(%ebp)

# Call _write(fd, buf, len)
mov    $0x1,%ebx		# Store "1" in EBX (the stdout fd)
lea    -0x14(%ebp),%ecx		# Store the address of the string on stack in ECX
mov    $0x8,%edx		# Store the length of the string in EDX
mov    $0x4,%eax		# Store the number of the syscall in EAX
int    $0x80

# Call the old entry point - here we should patch the '28' address which is the offset
# from the start of the symbol to the value that should be patched
call   28			# 

pop    %ecx
pop    %ebx
pop    %ebp
ret 
