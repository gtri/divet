import sys
import os
import struct

sys.path.append(os.path.join(os.path.dirname(__file__),"armcore.jar"))

from armcore import Arm
from armcore import Memory

class MemoryWrapper( Memory ):
	def __init__(self, mem):
		self.mem = mem
		
	def read16(self, aAddr):
		value, taint = self.mem.readWord(struct.unpack("<I",struct.pack("<i",aAddr))[0])
		return struct.unpack("<h",struct.pack("<H",value))[0]
		
	def read32(self, aAddr):
		value, taint = self.mem.readDword(struct.unpack("<I",struct.pack("<i",aAddr))[0])
		return struct.unpack("<i",struct.pack("<I",value))[0]

	def read8(self, aAddr):
		value, taint = self.mem.readByte(struct.unpack("<I",struct.pack("<i",aAddr))[0])
		return struct.unpack("<b",struct.pack("<B",value))[0]

	def write16(self, aAddr, aValue):
		self.mem.writeWord( struct.unpack("<I",struct.pack("<i",aAddr))[0], 
							struct.unpack("<H",struct.pack("<h",aValue))[0],
							0 )

	def write32(self, aAddr, aValue):
		self.mem.writeDword( struct.unpack("<I",struct.pack("<i",aAddr))[0], 
							struct.unpack("<I",struct.pack("<i",aValue))[0],
							0 )

	def write8(self, aAddr, aValue):
		self.mem.writeByte( struct.unpack("<I",struct.pack("<i",aAddr))[0], 
							struct.unpack("<B",struct.pack("<b",aValue))[0],
							0 )

							
class CPU( Arm ):
	regNames  = ["r0","r1","r2","r3","r4","r5","r6","r7","r8","r9","r10","fp","ip","sp","lr","pc","cpsr","spsr"]
	flagNames = ["n","z","c","v","q","it","j","ge","e","a","i","f","t","mode"]
	
	def __init__(self,mem):
		self.mem = MemoryWrapper(mem)
		Arm.__init__(self,self.mem,True)
		

	def getRegisters(self):
		return self
		
	def getMemory(self):
		return self.mem
	
	#Registers Interface
	def getRegister(self,name):
		name = name.lower()
		try:
			idx = self.regNames.index(name)
		except ValueError:
			pass
		else:
			value = struct.unpack("<I",struct.pack("<i",self.peekReg(idx)))[0]
			taint = struct.unpack("<I",struct.pack("<i",self.peekRegTaint(idx)))[0]
			return value, taint
			
		try:
			idx = self.flagNames.index(name)
		except ValueError:
			pass
		else:
			regValue = struct.unpack("<I",struct.pack("<i",self.peekReg(16)))[0]
			taint = struct.unpack("<I",struct.pack("<i",self.peekRegTaint(16)))[0]
			if idx == 0:
				value = int((regValue & (1L<<31)) != 0)
			elif idx == 1:
				value = int((regValue & (1L << 30)) != 0)
			elif idx == 2:
				value = int((regValue & (1L << 29)) != 0)
			elif idx == 3:
				value = int((regValue & (1L << 28)) != 0)
			elif idx == 4:
				value = int((regValue & (1L << 27)) != 0)
			elif idx == 5:
				value = int(((regValue >> 8) & 0xFC) | ((regValue >> 25) & 0x03))
			elif idx == 6:
				value = int((regValue & (1L << 24)) != 0)
			elif idx == 7:
				value = int((regValue >> 16) & 0x0F)
			elif idx == 8:
				value = int((regValue & (1L << 9)) != 0)
			elif idx == 9:
				value = int((regValue & (1L << 8)) != 0)
			elif idx == 10:
				value = int((regValue & (1L << 7)) != 0)
			elif idx == 11:
				value = int((regValue & (1L << 6)) != 0)
			elif idx == 12:
				value = int((regValue & (1L << 5)) != 0)
			else: #idx == 13
				value = int(regValue & 0x1f)
			return value, taint
			
		raise ValueError,"Bad register name: %s" % repr(name)

			
	def setRegister(self,name,value,taint):
		name = name.lower()
		
		try:
			idx = self.regNames.index(name)
		except ValueError:
			pass
		else:
			self.pokeReg(idx, struct.unpack("<i",struct.pack("<I",value))[0] )
			self.pokeRegTaint(idx, struct.unpack("<i",struct.pack("<I",taint))[0] )
			return
			
		try:
			idx = self.flagNames.index(name)
		except ValueError:
			pass
		else:
			regValue = struct.unpack("<I",struct.pack("<i",self.peekReg(16)))[0]
			if idx == 0:
				regValue = (regValue & 0x7FFFFFFF) | ((value&1)<31)
			elif idx == 1:
				regValue = (regValue & 0xBFFFFFFF) | ((value&1)<<30)
			elif idx == 2:
				regValue = (regValue & 0xDFFFFFFF) | ((value&1)<<29)
			elif idx == 3:
				regValue = (regValue & 0xEFFFFFFF) | ((value&1)<<28)
			elif idx == 4:
				regValue = (regValue & 0xF7FFFFFF) | ((value&1)<<27)
			elif idx == 5:
				regValue = (regValue & 0xF9FF03FF) | ((value&0xFC)<<8) | ((value&0x3)<<25) 
			elif idx == 6:
				regValue = (regValue & 0xFEFFFFFF) | ((value&1)<<24) 
			elif idx == 7:
				regValue = (regValue & 0xFFF0FFFF) | ((value&0xF)<<16)
			elif idx == 8:
				regValue = (regValue & 0xFFFFFDFF) | ((value&1)<<9)
			elif idx == 9:
				regValue = (regValue & 0xFFFFFEFF) | ((value&1)<<8)
			elif idx == 10:
				regValue = (regValue & 0xFFFFFF7F) | ((value&1)<<7)
			elif idx == 11:
				regValue = (regValue & 0xFFFFFFBF) | ((value&1)<<6)
			elif idx == 12:
				regValue = (regValue & 0xFFFFFFDF) | ((value&1)<<5)
			else: #idx == 13
				regValue = (regValue & 0xFFFFFFE0) | (value&0x1F)
			self.pokeReg(16, struct.unpack("<i",struct.pack("<I",regValue))[0] )
			self.pokeRegTaint(16, struct.unpack("<i",struct.pack("<I",int(taint)))[0] )
			return
			
		raise ValueError,"Bad register name: %s" % repr(name)
		
	def getRegistersDefinition(self):
		return [["General",[[self.regNames[i], self.regNames[i], 32] for i in xrange(11)]],
				["Special",[[self.regNames[i+11], self.regNames[i+11], 32] for i in xrange(7)]],
				["Flags",[["n","<html><u>N</u>egative</html>",1],["z","<html><u>Z</u>ero</html>",1],["c","<html><u>C</u>arry<html>",1],["v","<html>O<u>v</u>erflow</html>",1],["q","<html>Saturation(<u>Q</u>)",1],["it","<html><u>I</u>f <u>T</u>hen</html>",8],["j","j",1],["ge","<html><u>G</u>reater than or <u>E</u>qual</html>",4],["e","E",1],["a","A",1],["i","I",1],["f","F",1],["t","<html><u>T</u>humb</html>",1],["mode","mode",5]]]
			]
		
	def getProgramCounter(self):
		value, taint = self.getRegister("pc")
		return value
		
	def getStackPointerName(self):
		return "sp"
		
	def getState(self):
		regCount = len(self.regNames)
		values = [self.peekReg(i) for i in xrange(regCount)]
		taints = [self.peekRegTaint(i) for i in xrange(regCount)]
		state = struct.pack(">"+"ii"*regCount,*(values+taints))
		return state

	def setState(self,state):
		regCount = len(self.regNames)
		items = struct.unpack(">"+"ii"*regCount,state)
		for idx in xrange(regCount):
			self.pokeReg(idx,items[idx])
			self.pokeRegTaint(idx,items[idx+regCount])
			
	#CPU Interface
	def getSignals(self):
		return ["reset"]
		
	def signal(self,signalName):
		if signalName == "reset":
			self.reset()

	def step(self):
		Arm.step(self)
		print self.getOutput()