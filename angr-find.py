import angr
import logging
import sys


def solve():
    interact()


def explore(sm):
    if len(sys.argv) > 3:
        sm.explore(find=int(sys.argv[2], 16), avoid=int(sys.argv[3], 16))
    else:
        sm.explore(find=int(sys.argv[2], 16))

    if sm.found:
        logging.info("Found it!")
        s = sm.found[0]
        print(s.posix.stdin.concretize())
    else:
        print("Not found")
        interact()


def interact(l=None):
    if l:
        locals().update(l)
    import IPython
    IPython.embed(banner1='', confirm_exit=False)


if __name__ == '__main__':
    logging.getLogger('angr').setLevel(level=logging.INFO)

    proj = angr.Project(sys.argv[1])
    init_state = proj.factory.entry_state()
    sm = proj.factory.simgr(init_state)

    if len(sys.argv) > 2:
        explore()
    else:
        solve()

