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
Breakpoint 1 at 0x104fc: file vuln.c, line 5
(gdb) run < <(head -c 200 < /dev/zero | tr '\0' 'X')
Starting program: /home/src/1v4n/rop/vuln < <(head -c 200 < /dev/zero | tr '\0' 'X')
proot warning: ptrace request 'PTRACE_???' not supported yet
proot warning: ptrace request 'PTRACE_GETVFPREGS' not supported yet
proot warning: ptrace request 'PTRACE_GET_THREAD_AREA' not supported yet
warning: File "/usr/lib/libthread_db.so.1" auto-loading has been declined by your `auto-load safe-path' set to "$debugdir:$datadir/auto-load".
To enable execution of this file add
        add-auto-load-safe-path /usr/lib/libthread_db.so.1
line to your configuration file "/root/.config/gdb/gdbinit".
To completely disable this security protection add
        set auto-load safe-path /
line to your configuration file "/root/.config/gdb/gdbinit".
For more information about this security protection see the
"Auto-loading safe path" section in the GDB manual.  E.g., run from the shell:
        info "(gdb)Auto-loading safe path"
warning: Unable to find libthread_db matching inferior's thread library, thread debugging will not be available.

Breakpoint 1, fvuln (in=0xfffee708 'X' <repeats 200 times>) at vuln.c:5
5               printf("INPUT LEN: %zu\n", strlen(in));
(gdb) x/64x $sp
0xfffee6f0:     0xfffee708      0xfffee708      0x00000001      0x00011f14
0xfffee700:     0xfffee80c      0x000105c8      0x58585858      0x58585858
0xfffee710:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee720:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee730:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee740:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee750:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee760:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee770:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee780:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee790:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee7a0:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee7b0:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee7c0:     0x58585858      0x58585858      0x58585858      0x58585858
0xfffee7d0:     0xf7e6c700      0xf7fe5300      0x069691b4      0x0000001d
0xfffee7e0:     0xf7fe5000      0xf63d4e2e      0xf7e65358      0xf7e63e18
(gdb) info frame
Stack level 0, frame at 0xfffee708:
 pc = 0x104fc in fvuln (vuln.c:5); saved pc = 0x105c8
 called by frame at 0xfffee810
 source language c.
 Arglist at 0xfffee704, args: in=0xfffee708 'X' <repeats 200 times>
 Locals at 0xfffee704, Previous frame's sp is 0xfffee708
 Saved registers:
  r11 at 0xfffee700, lr at 0xfffee704
```
