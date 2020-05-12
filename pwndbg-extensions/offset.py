import pwndbg
import gdb
import argparse

parser = argparse.ArgumentParser(description='Find the offset to the base of the module containing the specified address')
parser.add_argument('address', type=int, help='The address to find the offset to')
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def offset(address):
    base_addr = pwndbg.elf.map(address)[0].start
    offset = address - base_addr
    print(f'Base = {hex(base_addr)}')
    gdb.execute(f'p/x {hex(address)} - {hex(base_addr)}')
