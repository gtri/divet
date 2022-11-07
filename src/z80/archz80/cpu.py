import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__),"z80core.jar"))

from z80core import Z80
from z80core import MemIoOps
from z80core import NotifyOps

class MemTranslator(MemIoOps):
	def __init__(self,mem):
		MemIoOps.__init__(self,0,0)
		self.mem = mem
		
	def fetchOpcode(self,address):
		self.tstates += 4
		return self.mem.readByte(address)[0]

	def peek8(self,address):
		self.tstates += 3
		return self.mem.readByte(address)[0]

	def poke8(self,address,value):
		self.tstates += 3
		self.mem.writeByte(address,value,False)

	def peek16(self,address):
		self.tstates += 6
		return self.mem.readWord(address)[0]

	def poke16(self,address, value):
		self.tstates += 6
		self.mem.writeWord(address,value,False)

	def inPort(self,port):
		self.tstates += 4
		return self.mem.readByte(port,"IO")[0]
		
	def outPort(self,port, value):
		self.tstates += 4
		self.mem.writeByte(port,value,False,"IO")

class DummyNotifyOps(NotifyOps):
	def breakpoint(self,address, opcode):
		print "ERROR: DummyNotifyOps.breakpoint was called"
		return 0
	def execDone(self):
		pass

class CPU(Z80):
	def __init__(self, regs, mem):
		Z80.__init__(self,MemTranslator(mem),DummyNotifyOps())
		regs.setCpu(self)
		
	def getSignals(self):
		return ["RESET","NMI","INT"]
		
	def signal(self,signalName,dataBytes=[0]):
		if signalName.upper() == "RESET":
			self.reset()
		elif signalName.upper() == "NMI":
			self.triggerNMI()
		elif signalName.upper() == "INT":
			self.interruption()
		
	def step(self):
		self.execute()

