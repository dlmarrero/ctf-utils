#!/usr/bin/env python
import subprocess
import sys
import os
import re
from pwn import log


LIBCDB_DIR = '/home/dmo/ctf/utils/libc-database'


class LIBCDB:
    # TODO handle multiple symbols
    def __init__(self, symbol, addr, libc_id=None, one_gadget=True):
        self.symbol = symbol
        self.addr = addr
        if not libc_id:
            self.libc_id = find_libc(symbol, hex(addr))
        else:
            self.libc_id = libc_id

        addrs = self._calculate_addrs()

        # Convenience vars for autocomplete goodness
        self.system = addrs['system']
        self.__libc_start_main_ret = addrs['__libc_start_main_ret']
        self.str_bin_sh = addrs['str_bin_sh']
        self.dup2 = addrs['dup2']
        self.write = addrs['write']
        self.read = addrs['read']
        self.base = addrs['base']
        self.addrs = addrs

        if one_gadget:
            self.one_gadget = self._init_one_gadget()
        else:
            self.one_gadget = None

    def _calculate_addrs(self):
        offsets = dump_libc(self.libc_id, self.symbol)
        offsets.update(dump_libc(self.libc_id))

        libc_base = self.addr - offsets[self.symbol]
        addrs = {'base': libc_base}

        for symbol in offsets.keys():
            addrs[symbol] = libc_base + offsets[symbol]

        return addrs

    def _init_one_gadget(self):
        oneg_results = run_one_gadget(self.libc_id)
        self._oneg_results = oneg_results

        # initialize one_gadget array
        one_gadgets = list()

        for res in oneg_results:
            lines = res.split('\n')
            
            words = lines[0].split()
            offset = int(words[0], 16)
            description = ' '.join(words[1:])

            address = self.base + offset
            constraints = [l.strip() for l in lines[1:] if 'constraints' not in l]
            one_gadgets.append(OneGadget(address, description, constraints))

        return one_gadgets

    def __str__(self):
        s = self.libc_id + '\n'
        s += '-' * 0x20 + '\n'
        for sym, addr in self.addrs.items():
            s += '%s = %s\n' % (sym, hex(addr))
        s += '-' * 0x20 + '\n'
        s += '\n\n'.join(self._oneg_results)
        s += '\n'
        return s


class OneGadget:
    def __init__(self, address, description, constraints):
        self.address = address
        self.description = description
        self.constraints = constraints

    def __str__(self):
        return '%s %s\n%s' % (hex(self.address), self.description, ' ; '.join(self.constraints))


def main():
    libc_id = find_libc(*sys.argv[1:])
    log.info(libc_id)

    separator()

    offsets = dump_libc(libc_id, sys.argv[1])
    offsets.update(dump_libc(libc_id))
    
    for sym, addr in offsets.items():
        log.info('%s = %s' % (sym, hex(addr)))

    separator()

    print_oneg_results(libc_id)


def get_offsets(symbol, addr, libc_id=None, run_oneg=False):
    if not libc_id:
        libc_id = find_libc(symbol, hex(addr))
    
    offsets = dump_libc(libc_id, symbol)
    offsets.update(dump_libc(libc_id))

    libc_base = addr - offsets[symbol]
    addrs = {'base': libc_base}

    for symbol in offsets.keys():
        addrs[symbol] = libc_base + offsets[symbol]

    if run_oneg:
        log.warning('Fetching one_gadget results...')
        print_oneg_results(libc_id)

    return addrs


def print_oneg_results(libc_id):
    oneg_results = run_one_gadget(libc_id)
    for res in oneg_results:
        lines = res.split('\n')
        log.info(lines[0])
        for l in lines[1:]:
            print('    %s' % l)
        print('')


def find_libc(*args):
    find_argv = [os.path.join(LIBCDB_DIR, 'find')] + list(args)
    proc = subprocess.Popen(find_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    matches = proc.stdout.readlines()

    if not matches:
        log.warning('No matches found for "%s" in libc db!' % ' '.join(args))
        exit(1)

    if len(matches) > 1:
        selection = prompt_for_match(matches)
    else:
        selection = matches[0]

    lib_id = extract_id(selection)
    return lib_id


def dump_libc(libc_id, symbol=None):
    dump_argv = [os.path.join(LIBCDB_DIR, 'dump'), libc_id]
    if symbol:
        dump_argv.append(symbol)

    proc = subprocess.Popen(dump_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    offsets = {}
    for line in proc.stdout.readlines():
        l = line.decode()
        symbol, addr = l.split(' = ')
        offsets[symbol.replace('offset_', '')] = int(addr, 16)

    return offsets


def run_one_gadget(libc_id):
    oneg_argv = ['one_gadget', os.path.join(LIBCDB_DIR, 'db', libc_id + '.so')]
    proc = subprocess.Popen(oneg_argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    results = proc.stdout.read().split('\n\n')
    return results


def prompt_for_match(matches):
    log.warning('SELECT LIBC VERSION')
    for i, m in enumerate(matches):
        log.info('%d: %s' % (i+1, m))

    sel = int(input('> '))
    print('')

    return matches[sel-1]


def extract_id(selection):
    p = re.compile('id (.*)\)')
    m = p.search(selection)
    return m.group(1)


def separator():
    print('-' * 0x20)


if __name__ == '__main__':
    main()

