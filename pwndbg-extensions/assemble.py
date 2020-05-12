import pwndbg
import gdb
import argparse
import sys
import os

# Must be set before importing pwntools
os.environ['PWNLIB_NOTERM'] = 'true'

from pwn import asm,context,PwnlibException


# TODO: include a jmp patching option... maybe too much
parser = argparse.ArgumentParser(description="Starting at the specified address, write the assembled instructions")
parser.add_argument("address", type=int, help="The address to start assembling at")
parser.add_argument("code", type=str, default='', nargs='?', help="The code to be assembled")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def assemble(address, code):
    try:
        # Get the current architecture from pwndbg
        context.update(arch=pwndbg.arch.current, os='linux')
    except:
        raise ValueError("Unsupported architecture: {pwndbg.arch.current}")

    # Check if the address is mapped
    if not pwndbg.memory.poke(address):
        try:
            # mmap a new page at the specified address 
            mapped_addr = long(str(gdb.parse_and_eval('mmap(0x%x, 0x1000, 7, 0x32, -1, 0)' % address)), 16)
        except pwndbg.gdb.error:
            # Handle binaries where symbol for mmap is not loaded
            raise Exception(f"Address {hex(address)} is not mapped and mmap symbol not in current context")

        # mmap returns -1 on failure, we check for 32b and 64b -1
        if mapped_addr == 0xffffffffffffffff or mapped_addr == 0xffffffff:
            raise Exception("Call to mmap with address 0x%x failed" % address)
    
        print("Mapped new memory region at 0x%x" % mapped_addr)

        # Update address where we'll write instructions
        address = mapped_addr

    # Prompt for instructions when code arg is not supplied
    if not code:
        print("Enter assembly instructions one per line")
        print("Enter 'EOF' when done")
        while True:
            ins = input('> ')
            if 'EOF' in ins:
                break
            code += ins + '\n'
    
    try:
        # Assemble the instructions
        asm_str = asm(code)
    except PwnlibException as e:
        # Handle bad instructions
        raise Exception("Failed to assemble. Check your instructions.")
    
    # Write the assembled code to the specified address
    pwndbg.memory.write(address, asm_str)

