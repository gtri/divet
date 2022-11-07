from ghidra.pcode.memstate import MemoryState
from ghidra.pcode.memstate import MemoryBank
from ghidra.pcode.memstate import MemoryFaultHandler
from ..EndianEmulatedMemory import BigEndianEmulatedMemory,LittleEndianEmulatedMemory

import traceback
import struct

class EmulatedMemoryFaultHandler( MemoryFaultHandler ):
	def __init__(self):
		MemoryFaultHandler.__init__(self)
		
	def uninitializedRead(self, address, size, buf, bufOffset):
		print "uninitializedRead(",repr(address),",",repr(size),",",repr(buf),",",repr(bufOffset),")"
		
	def unknownAddress(self, address, write):
		print "unknownAddress(",repr(adress),",",repr(write),")"
	

class EmulatedMemoryBank( MemoryBank ):
	def __init__(self, memState, addressSpace):
		self.memState = memState
		self.addressSpace = addressSpace
		
		#Calculate pageSize
		size = addressSpace.getMaxAddress().getOffset() - addressSpace.getMinAddress().getOffset()
		pageSize = 1024
			
		#Initialize the parent MemoryBank
		isBigEndian = isinstance(self.memState.mem,BigEndianEmulatedMemory)
		MemoryBank.__init__(self, addressSpace, isBigEndian, pageSize, EmulatedMemoryFaultHandler())
		
	def getChunk(self, offset, size, result, stopOnUnintialized):
		#This Ignores stopOnUnintialized
		#This try/except is here because otherwise Python 
		#exceptions get caught and masked by Java
		try:
			if offset < 0:
				offset = struct.unpack(">L",struct.pack(">l",offset))[0]
			if self.addressSpace.isRegisterSpace():
				bytes, taint = self.memState.registers.getRegisterByOffset(offset,size)
				for i in xrange(size):
					result[i] = struct.unpack(">b",struct.pack(">B",bytes[i]))[0]
			else:
				bankName = self.addressSpace.getName()
				if not len(bankName):
					bankName = None
				for i in xrange(size):
					byte, taint = self.memState.mem.readByte(offset+i,bankName)
					byte = struct.unpack(">b",struct.pack(">B",byte))[0]
					result[i] = byte
			self.memState.taint = self.memState.taint | taint
		except:
			traceback.print_exc()
		return size

	def setChunk(self, offset, size, value):
		#This try/except is here because otherwise Python 
		#exceptions get caught and masked by Java
		try:
			if offset < 0:
				offset = struct.unpack(">L",struct.pack(">l",offset))[0]
			
			bytes = []
			for i in xrange(size):
				try:
					byte = struct.unpack(">B",struct.pack(">b",value[i]))[0]
				except IndexError:
					byte = 0
				bytes.append( byte )

			if self.addressSpace.isRegisterSpace():
				self.memState.registers.setRegisterByOffset(offset,size,bytes,self.memState.taint)
			else:
				bankName = self.addressSpace.getName()
				if not len(bankName):
					bankName = None
				for i in xrange(size):
					self.memState.mem.writeByte(offset+i,bytes[i],self.memState.taint,bankName)
		except:
			traceback.print_exc()

class EmulatedMemoryState( MemoryState ):
	def __init__(self,registers,ghidraState,historySize=0):
		MemoryState.__init__(self,ghidraState.getCurrentProgram().getLanguage())
		
		#registers and taint are accessed directly by EmulatedMemoryBanks
		self.registers = registers
		self.taint = 0
		
		ghidraProgram = ghidraState.getCurrentProgram()
		ghidraLanguage = ghidraProgram.getLanguage()
		addressFactory = ghidraLanguage.getAddressFactory()
		
		#Figure out the address width and create the BigEndianEmulatedMemory
		maxAddress = 0
		
		#getAllPhysicalSpaces() does not work properly on virtual memory executables
		#so default to getAllAddressSpaces().  Even though this will include registers, etc.
		for addressSpace in addressFactory.getAllAddressSpaces():
			end = addressSpace.getMaxAddress().getOffset()
			if end > maxAddress:
				maxAddress = end
		addressWidth = 1
		while (1<<(addressWidth-1)) < maxAddress:
			addressWidth = addressWidth + 1
		#mem is accessed directly by EmulatedMemoryBanks
		if ghidraLanguage.isBigEndian():
			self.mem = BigEndianEmulatedMemory(ghidraProgram,addressWidth,0,historySize)
		else:
			self.mem = LittleEndianEmulatedMemory(ghidraProgram,addressWidth,0,historySize)
		
		#Cycle through the addressSpaces again and add banks to the memory
		for addressSpace in addressFactory.getPhysicalSpaces():
			bank = EmulatedMemoryBank(self,addressSpace)
			self._setMemoryBank(bank)
		#Add the register address space bank
		bank = EmulatedMemoryBank(self,addressFactory.getRegisterSpace())
		self.setMemoryBank(bank)
		
	def getEmulatedMemory(self):
		return self.mem

	def resetTaint(self):
		self.taint = 0

	def _setMemoryBank(self, memoryBank):
		addressSpace = memoryBank.getSpace()
		name = addressSpace.getName()
		start = addressSpace.getMinAddress().getOffset()
		if start < 0:
			start = struct.unpack(">L",struct.pack(">l",start))[0]
		end = addressSpace.getMaxAddress().getOffset()
		if end < 0 :
			end = struct.unpack(">L",struct.pack(">l",end))[0]
		self.mem.addBank(name,start,end,activate=True,default=False)
		self.setMemoryBank(memoryBank)
		
