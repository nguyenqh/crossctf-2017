#!/usr/bin/python

from pwn import *

def main() :
	p = process("./skypillar")
	raw_input(str(p.proc.pid))

	# p = remote("192.168.0.250", 1350)

	payload = "A" * 260
	code = [0x40772049, 0x20406e6e, 0x74206562, 0x76206568, 0x20797265, 0x74736562, 0x00000000]
	code_str = ''.join([p32(c) for c in code])

	log.info("Code: %s" % code_str)
	p.sendline(code_str)


	data = p.recvrepeat(0.2)
	log.info(data)

	p.sendline("A@CAG")

	data = p.recvrepeat(0.2)
	log.info(data)

	p.sendline(str(592))

	data = p.recvrepeat(0.2)
	log.info(data)

	p.interactive()
	

if __name__ == "__main__":
	main()