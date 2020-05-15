import pwndbg
import socket


class Ghidra:
    # TODO can we get the decompiled code while we're at it?
    # TODO send base addr on connection to rebase in Ghidra
    def __init__(self, ghidra_port):
        # sets self._sock and self.connected
        self.connect(ghidra_port)

    def set_location(self, addr):
        self._sendline('location-%s' % hex(addr))

    def run_command(self, cmd, arg):
        if not self.connected:
            print('Cannot run command: Not connected')
            return
        
        print('Sending command: %s (%s)' % (cmd, arg))
        self._sendline('-'.join(cmd, arg))
        ack = self._recvline()
        if not ack and not self.connected:
            print('Lost connection to Ghidra while awaiting ack')

    def close_conn(self):
        self._sendline('close-0')
        self._sock.close()
        self.connected = False

    def connect(self, ghidra_port):
        s = socket.socket()
        try:
            s.connect(('127.0.0.1', ghidra_port))
            self.connected = True
        except socket.error:
            s.close()
            self.connected = False
            print('Failed to connect to Ghidra on localhost:%d' % ghidra_port)
        
        self._sock = s

    def _sendline(self, msg):
        self._sock.sendall(msg.encode() + b'\n')
        
    def _recvline(self):
        res = b''
        while '\n' not in res:
            c = self._sock.recv(1)
            if not c:
                self.connected = False
                return None
            res += c
            
        return res.decode().strip()


@pwndbg.events.stop
def send_current_pc():
    if ghidra.connected:
        # get current pc
        pc = pwndbg.regs[pwndbg.regs.current.pc]
        ghidra.set_location(pc)

@pwndbg.events.exit
def close_sock():
    if ghidra.connected:
        ghidra.close_conn()


ghidra = Ghidra(1337)
