from pwn import *

context.update(arch='arm', os='linux')

elf = ELF('./vuln')
p = process('./vuln')

gdb.attach(p, '''
  break fvuln
  continue
''')

with open('exploit.bin', 'rb') as f:
    payload = f.read()

p.send(payload)
p.interactive()
