import pwndbg
import gdb
import argparse
import six

parser = argparse.ArgumentParser(description='Find the offset to the base of the module containing the specified address')
parser.add_argument('address_or_symbol', help='The address or symbol to find the offset to')
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def offset(address_or_symbol):
    # Handle either a symbol or an addr (offset puts || offset 0x7fffe000)
    gdb_val = pwndbg.commands.sloppy_gdb_parse(address_or_symbol)
    if gdb_val.address:
        address = int(gdb_val.address)
    else:
        address = int(gdb_val)

    base_addr = pwndbg.elf.map(address)[0].start
    print('Addr = %s' % hex(address))
    print('Base = %s' % hex(base_addr))
    gdb.execute('p/x %s' % hex(address - base_addr))
