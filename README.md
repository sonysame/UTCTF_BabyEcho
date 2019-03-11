# UTCTF_BabyEcho
pwnable 

### format string attack
overwrite exit@got in order to go back to main  
by using format string attack, we can leak libc address  
overwrite printf@got with the address of system

Also, we will use libc database to execute in remote server
