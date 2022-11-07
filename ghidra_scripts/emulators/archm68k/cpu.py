import sys
import os
import struct

sys.path.append(os.path.join(os.path.dirname(__file__),"m68k.jar"))

from m68k.cpu import MC68000
from m68k.memory import AddressSpace
from m68k import TaintedValue

import jarray
from java.nio import ByteBuffer

def _pyInt32(num):
	if num < 0:
		num = struct.unpack(">I",struct.pack(">i",num))[0]
	return num
	
def _jInt32(num):
	if num > 0x7fffffff:
		num = struct.unpack(">i",struct.pack(">I",num))[0]
	return num

#This registers object is the _real_ CPU object
#for this architecture due to how the java CPU
#class is implmented
class Registers(MC68000):
	def __init__(self):
		pass
	
	def getRegister(self,name):
		try:
			if len(name) < 1:
				raise ValueError,"Invalid register name: %s" % repr(name)
		except TypeError:
			raise ValueError,"Invalid register name: %s" % repr(name)
		if name == "c":
			if self.isFlagSet(self.C_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "v":
			if self.isFlagSet(self.V_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "z":
			if self.isFlagSet(self.Z_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "n":
			if self.isFlagSet(self.N_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "x":
			if self.isFlagSet(self.X_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "t":
			if self.isFlagSet(self.TRACE_FLAG):
				return 1, 0
			else:
				return 0, 0
		elif name == "s":
			if self.isSupervisorMode():
				return 1, 0
			else:
				return 0, 0
		elif name == "int":
			return self.getInterruptLevel(), 0
		elif name == "usp":
			r = self.getUSP()
			return _pyInt32(r.value), r.tainted
		elif name == "ssp":
			r = self.getSSP()
			return _pyInt32(r.value), r.tainted
		elif name == "pc":
			r = self.getPC()
			return _pyInt32(r.value), r.tainted
		elif name[0] == "d":
			err = False
			try:
				idx = int(name[1:])
			except ValueError:
				err = True
			else:
				if idx < 0 or idx > 7:
					err = True
			if err:
				raise ValueError,"Invalid register name: %s" % repr(name)
			r = self.getDataRegisterLong(idx)
			return _pyInt32(r.value), r.tainted
		elif name[0] == "a":
			err = False
			try:
				idx = int(name[1:])
			except ValueError:
				err = True
			else:
				if idx < 0 or idx > 7:
					err = True
			if err:
				raise ValueError, "Invalid register name: %s" % repr(name)
			r = self.getAddrRegisterLong(idx)
			return _pyInt32(r.value), r.tainted
		else:
			raise ValueError, "Invalid register name: %s" % repr(name)
	
	def setRegister(self,name,value,tainted):
		try:
			if len(name) < 1:
				raise ValueError, "Invalid register name: %s" % repr(name)
		except TypeError:
			raise ValueError, "Invalid register name: %s" % repr(name)
		if name == "c":
			if value:
				self.setFlags(self.C_FLAG)
			else:
				self.clrFlags(self.C_FLAG)
		elif name == "v":
			if value:
				self.setFlags(self.V_FLAG)
			else:
				self.clrFlags(self.V_FLAG)
		elif name == "z":
			if value:
				self.setFlags(self.Z_FLAG)
			else:
				self.clrFlags(self.Z_FLAG)
		elif name == "n":
			if value:
				self.setFlags(self.N_FLAG)
			else:
				self.clrFlags(self.N_FLAG)
		elif name == "x":
			if value:
				self.setFlags(self.Z_FLAG)
			else:
				self.clrFlags(self.Z_FLAG)
		elif name == "t":
			if value:
				self.setFlags(self.TRACE_FLAG)
			else:
				self.clrFlags(self.TRACE_FLAG)
		elif name == "s":
			if value:
				self.setSupervisorMode(True)
			else:
				self.setSupervisorMode(False)
		elif name == "int":
			return self.setInterruptLevel(int(value))
		elif name == "usp":
			self.setUSP(TaintedValue( _jInt32(int(value)), tainted))
		elif name == "ssp":
			self.setSSP(TaintedValue( _jInt32(int(value)), tainted))
		elif name == "pc":
			return self.setPC(TaintedValue( _jInt32(int(value)), tainted))
		elif name[0] == "d":
			err = False
			try:
				idx = int(name[1:])
			except ValueError:
				err = True
			else:
				if idx < 0 or idx > 7:
					err = True
			if err:
				raise ValueError, "Invalid register name: %s" % repr(name)
			self.setDataRegisterLong(idx,TaintedValue( _jInt32(int(value)), tainted))
		elif name[0] == "a":
			err = False
			try:
				idx = int(name[1:])
			except ValueError:
				err = True
			else:
				if idx < 0 or idx > 7:
					err = True
			if err:
				raise ValueError, "Invalid register name: %s" % repr(name)
			self.setAddrRegisterLong(idx,TaintedValue( _jInt32(int(value)), tainted))
		else:
			raise ValueError, "Invalid register name: %s" % repr(name)
		
	def getRegistersDefinition(self):
		return [
			["Data", [	["d0", "D0", 32],
						["d1", "D1", 32],
						["d2", "D2", 32],
						["d3", "D3", 32],
						["d4", "D4", 32],
						["d5", "D5", 32],
						["d6", "D6", 32],
						["d7", "D7", 32]]],
			["Address",[["a0", "A0", 32],
						["a1", "A1", 32],
						["a2", "A2", 32],
						["a3", "A3", 32],
						["a4", "A4", 32],
						["a5", "A5", 32],
						["a6", "A6", 32],
						["a7", "A7", 32]]],
			["Flags",  [["c",	"<HTML><U>C</U>arry</HTML>",			1],
						["v",	"<HTML>O<U>v</U>erflow</HTML>",			1],
						["z",	"<HTML><U>Z</U>ero</HTML>",				1],
						["n",	"<HTML><U>N</U>egative</HTML>",			1],
						["x",	"<HTML>e<U>X</U>tend</HTML>",			1],
						["int",	"<HTML><U>Int</U>errupt Level</HTML>",	3],
						["s",	"<HTML><U>S</U>upervisor</HTML>",		1],
						["t",	"<HTML><U>T</U>race</HTML>",			1]]],
			["Misc",   [["usp",	"<HTML><U>U</U>ser <U>SP</U></HTML>",	32],
						["ssp",	"<HTML><U>S</U>uper <U>SP</U></HTML>",	32],
						["pc",	"PC", 32]]],
			]
	
	def getProgramCounter(self):
		return _pyInt32(self.getPC().value)
		
	def getStackPointerName(self):
		return "a7"
		
	def getState(self):
		state = MC68000.getState(self).array()
		return struct.pack("b"*len(state),*state)
		
	def setState(self,state):
		byte_buffer = ByteBuffer.wrap(jarray.array(struct.unpack("b"*len(state),state),"b"))
		MC68000.setState(self,byte_buffer)
	

class MemoryTranslator(AddressSpace):
	def __init__(self, emuMem):
		self.mem = emuMem
	
	def reset(self):
		self.mem.reset()
		
	def getStartAddress(self):
		return 0
		
	def getEndAddress(self):
		return self.mem.addressMax

	def readByte(self, addr):
		value, tainted = self.mem.readByte(_pyInt32(addr))
		return TaintedValue(_jInt32(value), tainted)
		
	def readWord(self, addr):
		value, tainted = self.mem.readWord(_pyInt32(addr))
		return TaintedValue(_jInt32(value), tainted)
		
	def readLong(self, addr):
		value, tainted = self.mem.readDword(_pyInt32(addr))
		return TaintedValue(_jInt32(value), tainted)

	def writeByte(self, addr, value):
		self.mem.writeByte(_pyInt32(addr), _pyInt32(value.value), value.tainted)
		
	def writeWord(self, addr, value):
		self.mem.writeWord(_pyInt32(addr), _pyInt32(value.value), value.tainted)
			
	def writeLong(self, addr, value):
		self.mem.writeDword(_pyInt32(addr), _pyInt32(value.value), value.tainted)

	def internalReadByte(self, addr):
		return self.readByte(addr)
	def internalReadWord(self, addr):
		return self.readWord(addr)
	def internalReadLong(self, addr):
		return self.readLong(addr)
	def internalWriteByte(self, addr, value):
		self.writeByte(addr,value)
	def internalWriteWord(self, addr, value):
		self.writeWord(addr,value)
	def internalWriteLong(self, addr, value):
		self.writeLong(addr,value)

	def size(self):
		return self.getEndAddress() + 1

class CPU:
	def __init__(self, registers, memory):
		memTrans = MemoryTranslator(memory)
		registers.setAddressSpace(memTrans)
		registers.reset()
		self.javaCpu = registers

	def getSignals(self):
		return ["INT0","INT1","INT2","INT3","INT4","INT5","INT6","INT7"]
		
	def signal(self,signalName):
		if signalName.upper()[:3] != "INT":
			return
		try:
			priority = int(signalName[3:])
		except ValueError:
			return
		self.javaCpu.raiseInterrupt(priority)

	def step(self):
		self.javaCpu.execute()
