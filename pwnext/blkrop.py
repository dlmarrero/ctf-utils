from pwn import ROP, log

class BlkROP(ROP):
    def find_gadget(self, insns):
        if type(insns) is str:
            insns = [insn.strip() for insn in insns.split(';')]

        found_gadget = super(BlkROP, self).find_gadget(insns)

        if not found_gadget:
            raise Exception('Gadget %s not found' % insns)

        log.debug('ROP 0x%x %s' % (found_gadget.address, ' ; '.join(found_gadget.insns)))
        return found_gadget

    def common(self):
        gadgets = {
            'pop_rdi': self.find_gadget('pop rdi').address,
            'pop_rsi': self.find_gadget('pop rsi').address,
            'pop_rdx': self.find_gadget('pop rdx').address
        }
        
        return gadgets

