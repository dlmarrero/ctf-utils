from pwn import gdb

def set_bp(io, *args):
    gdbscript = ''
    for breakpoint in args:
        if type(breakpoint) == str:
            gdbscript += 'b %s\n' % breakpoint
            continue
        elif type(breakpoint) == tuple:
            addr, cmd_list = breakpoint
            assert type(cmd_list) == list

            bp_cmds = 'commands\n'
            bp_cmds += '\n'.join(cmd_list)
            bp_cmds += '\nend\n'
        else:
            addr = breakpoint
            bp_cmds = ''

        gdbscript += 'bp 0x%x\n%s' % (addr, bp_cmds)

    if args:
        gdbscript += 'c'

    try:
        gdb.attach(io, gdbscript)
    except AttributeError:
        # hack to fix libc docker containers
        pass
