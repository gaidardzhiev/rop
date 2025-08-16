# ARM32 ROP Exploit Project

## Overview
This project demonstrates a practical Return-Oriented Programming (ROP) exploit on an ARM32 Linux environment using Termux on Android. The goal is to exploit a simple stack buffer overflow vulnerability in a custom C program to execute arbitrary code.

## Vulnerable Program
- A minimal C program (`vuln.c`) that reads input from `stdin` into a fixed size buffer without proper bounds checking, allowing for buffer overflow.
- Compiled with no stack protection, non PIE, and executable stack to facilitate exploitation.

### Compilation
Run `make` or:
```
gcc -marm -fno-stack-protector -z execstack -no-pie -g -o vuln vuln.c
```

## Testing Overflow
- The program accepts input from `stdin`.
- Use this command to trigger overflow with a controlled input size:
```
head -c 200 < /dev/zero | tr '\0' 'X' | ./vuln
```
- Confirm overflow by observing crash or abnormal behavior.

## Analysis with GDB
```
gdb ./vuln
(gdb) break fvuln
(gdb) run < <(head -c 200 < /dev/zero | tr '\0' 'X')
(gdb) info frame
(gdb) x/64x $sp
```
