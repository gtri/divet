from EmulatedMemory import EmulatedMemory,AREAD,AREADIDX,AWRITE

class EndianEmulatedMemory(EmulatedMemory):
	def __init__(self, ghidraProgram=None, addressWidth=16, defaultValue=0, historySize=0):
		EmulatedMemory.__init__(self,ghidraProgram,addressWidth,1,defaultValue,historySize)
		self.endianByteWidth = 1
		self.endianCellFormat = "%02X"

	def setByteWidth(self,byteWidth):
		self.endianByteWidth = byteWidth
		self.endianCellFormat = "%%0%dX" % (byteWidth*2)

	def setTaint(self, address, taint, bankName=None):
		for i in xrange(self.endianByteWidth):
			EmulatedMemory.setTaint(self,address+i,taint, bankName)
			
	def getTaint(self, address, bankName=None):
		overallTaint = 0
		for i in xrange(self.endianByteWidth):
			overallTaint = overallTaint | EmulatedMemory.getTaint(self,address+i,bankName)
		return overallTaint
			
	def isTainted(self, address, bankName=None):
		overallTainted = False
		for i in xrange(self.endianByteWidth):
			overallTainted = overallTainted or EmulatedMemory.isTainted(self,address+i,bankName)
		return overallTainted
		
	def isManuallyTainted(self, address, bankName=None):
		overallTainted = False
		for i in xrange(self.endianByteWidth):
			overallTainted = overallTainted or EmulatedMemory.isManuallyTainted(self,address+i,bankName)
		return overallTainted
		
	def setReadValues(self, address, values, bankName=None):
		byteSets = [[] for i in xrange(self.endianByteWidth)]
		for value in values:
			bytes = self._value2Bytes(value)
			for i in xrange(self.endianByteWidth):
				byteSets[i].append(bytes[i])
		for i in xrange(self.endianByteWidth):
			EmulatedMemory.setReadValues(self, address + i, byteSets[i], bankName)
			
	def getReadValues(self, address, bankName=None):
		byteSets = [[] for i in xrange(self.endianByteWidth)]
		for i in xrange(self.endianByteWidth):
			byteValues = EmulatedMemory.getReadValues(self, address + i, bankName)
			for b in byteValues:
				byteSets[i].append(b)
		if sum([1 for i in xrange(len(byteSets)) if len(byteSets[i]) != len(byteSets[0])]):
			return None
		values = []
		for v in xrange(len(byteSets[0])):
			bytes = [byteSets[i][v] for i in xrange(self.endianByteWidth)] 
			values.append(self._bytes2Value(bytes))
		return values
			
	def getReadValuesString(self, address, bankName=None):
		values = self.getReadValues(address,bankName)
		if values == None:
			return "?"
		else:
			return ", ".join([self.getValueString(value) for value in values])
		
	def setStoredValue(self, address, value, bankName=None):
		values = self._value2Bytes(value)
		for i in xrange(self.endianByteWidth):
			EmulatedMemory.setStoredValue(self, address + i, values[i], bankName)
		
	def getStoredValue(self, address, bankName=None):
		values = [EmulatedMemory.getStoredValue(self, address + i, bankName) for i in xrange(self.endianByteWidth)]
		if None in values:
			return None
		else:
			return self._bytes2Value(values)
			
	def getStoredValueString(self, address, bankName=None):
		value = self.getStoredValue(address, bankName)
		if value == None:
			return "?"
		else:
			return self.getValueString(value)

	def setMutable(self, address, mutable, bankName=None):
		for i in xrange(self.endianByteWidth):
			EmulatedMemory.setMutable(self, address + i, mutable, bankName)
	
	def isMutable(self, address, bankName=None):
		overallMutable = True
		for i in xrange(self.endianByteWidth):
			overallMutable = overallMutable and EmulatedMemory.isMutable(self, address + i, bankName)
		return overallMutable
	
	def getValueString(self, value):
		return self.endianCellFormat % value
	
	def read(self, address, bankName=None):
		value, tainted = EmulatedMemory.read(self, address, bankName)
		self.history[-1].append(self.endianByteWidth)
		return value, tainted
	
	def _read(self, address, readInc=False, bankName=None):
		overallTainted = False
		bytes = []
		retBank = None
		retAccess = AREAD
		retAddress = None
		for i in xrange(self.endianByteWidth):
			byteBank, byteAccess, byteAddress, byte, tainted = EmulatedMemory._read(self, address + i, readInc, bankName)
			if retBank == None: retBank = byteBank
			if byteAccess == AREADIDX: retAccess = AREADIDX
			if retAddress == None: retAddress = byteAddress
			bytes.append(byte)
			overallTainted = overallTainted or tainted
		value = self._bytes2Value(bytes)
		return retBank, retAccess, retAddress, value, tainted

	def write(self, address, value, tainted, bankName=None):
		EmulatedMemory.write(self, address, value, tainted, bankName)
		self.history[-1].append(self.endianByteWidth)

	def _write(self, address, value, tainted, bankName=None):
		bytes = self._value2Bytes(value)
		prevBytes = []
		prevBytesTainted = []
		retBank = None
		retAddress = None
		for i in xrange(self.endianByteWidth):
			byteBank, byteAddress, prevValue, prevTainted = EmulatedMemory._write(self, address + i, bytes[i], tainted, bankName)
			if retBank == None: retBank = byteBank
			if retAddress == None: retAddress = byteAddress
			prevBytes.append(prevValue)
			prevBytesTainted.append(prevTainted)
		return retBank, retAddress, prevBytes, prevBytesTainted

	def undoStep(self):
		if not len(self.historySteps):
			return False
		count = self.getStepRecordSize()
		if len(self.history) < count:
			return False
		for i in xrange(count):
			record = self.history[-1]
			bankName, accessType, address, value, tainted = record[:5]
			byteWidth = record[-1]
			if self.logger != None:
				self.logger.logMemoryUndoAccess(bankName, accessType, address, value, tainted)
			for j in xrange(byteWidth):
				if accessType == AWRITE:
					prevValue = record[5][j]
					prevTainted = record[6][j]
					byteRecord = [bankName, accessType, address+j, value, tainted, prevValue, prevTainted]
				else:
					byteRecord = [bankName, accessType, address+j, value, tainted]
				self._undoAccess(byteRecord)
			self.history = self.history[:-1]
		self.historySteps = self.historySteps[:-1]
		return True

	#
	# Additional convience Functions
	#
	def readByte(self, address, bankName=None):
		self.setByteWidth(1)
		return self.read(address, bankName)
		
	def readWord(self, address, bankName=None):
		self.setByteWidth(2)
		return self.read(address, bankName)
		
	def readDword(self, address, bankName=None):
		self.setByteWidth(4)
		return self.read(address, bankName)
		
	def readQword(self, address, bankName=None):
		self.setByteWidth(8)
		return self.read(address, bankName)

	def writeByte(self, address, value, tainted, bankName=None):
		self.setByteWidth(1)
		return self.write(address, value, tainted, bankName)
		
	def writeWord(self, address, value, tainted, bankName=None):
		self.setByteWidth(2)
		return self.write(address, value, tainted, bankName)
		
	def writeDword(self, address, value, tainted, bankName=None):
		self.setByteWidth(4)
		return self.write(address, value, tainted, bankName)
		
	def writeQword(self, address, value, tainted, bankName=None):
		self.setByteWidth(8)
		return self.write(address, value, tainted, bankName)
		
	def getByte(self, address, bankName=None):
		self.setByteWidth(1)
		return self.getMemory(address, bankName)
		
	def getWord(self, address, bankName=None):
		self.setByteWidth(2)
		return self.getMemory(address, bankName)
				
	def getDword(self, address, bankName=None):
		self.setByteWidth(4)
		return self.getMemory(address, bankName)
				
	def getQword(self, address, bankName=None):
		self.setByteWidth(8)
		return self.getMemory(address,bankName)
		
	def setByte(self, address, value, tainted, bankName=None):
		self.setByteWidth(1)
		self.setMemory(address,value,tainted,bankName)
		
	def setWord(self, address, value, tainted, bankName=None):
		self.setByteWidth(2)
		self.setMemory(address,value,tainted,bankName)
		
	def setDword(self, address, value, tainted, bankName=None):
		self.setByteWidth(4)
		self.setMemory(address,value,tainted,bankName)
		
	def setQword(self, address, value, tainted, bankName=None):
		self.setByteWidth(8)
		self.setMemory(address,value,tainted,bankName)
	
	def setByteReadValues(self, address, values, bankName=None):
		self.setByteWidth(1)
		self.setReadValues(address, values, bankName)
		
	def setWordReadValues(self, address, values, bankName=None):
		self.setByteWidth(2)
		self.setReadValues(address, values, bankName)
		
	def setDwordReadValues(self, address, values, bankName=None):
		self.setByteWidth(4)
		self.setReadValues(address, values, bankName)
		
	def setQwordReadValues(self, address, values, bankName=None):
		self.setByteWidth(8)
		self.setReadValues(address, values, bankName)
		
	def getByteReadValues(self, address, bankName=None):
		self.setByteWidth(1)
		return self.getReadValues(address, bankName)
		
	def getWordReadValues(self, address, bankName=None):
		self.setByteWidth(2)
		return self.getReadValues(address, bankName)
		
	def getDwordReadValues(self, address, bankName=None):
		self.setByteWidth(4)
		return self.getReadValues(address, bankName)
		
	def getQwordReadValues(self, address, bankName=None):
		self.setByteWidth(8)
		return self.getReadValues(address, bankName)



class BigEndianEmulatedMemory(EndianEmulatedMemory):
	def _value2Bytes(self,value):
		bytes = []
		for i in xrange(self.endianByteWidth):
			bytes.append(value & 0xFF)
			value = value >> 8
		bytes.reverse()
		return bytes
		
	def _bytes2Value(self,bytes):
		value = 0
		while len(bytes) < self.endianByteWidth:
			bytes = [0]+bytes
		for i in xrange(self.endianByteWidth):
			value = (value << 8) | (bytes[i] & 0xFF)
		return value
			
		
class LittleEndianEmulatedMemory(EndianEmulatedMemory):
	def _value2Bytes(self,value):
		bytes = []
		for i in xrange(self.endianByteWidth):
			bytes.append(value & 0xFF)
			value = value >> 8
		return bytes
		
	def _bytes2Value(self,bytes):
		value = 0
		while len(bytes) < self.endianByteWidth:
			bytes = bytes + [0]
		for i in xrange(self.endianByteWidth):
			value = value | ((bytes[i] & 0xFF) << (i * 8))
		return value

#This class provides the same interface as BigEndianEmulatedMemory/LittleEndianEmulatedMemory,
#but retains the single cell per value concept of EmulatedMemory.  This is here so other
#classes can be built to use EndianEmulatedMemory, but we can still go back to a regular
#EmulatedMemory if we want.
class NonEndianEmulatedMemory(EmulatedMemory):
	def __init__(self, ghidraProgram=None, addressWidth=16, defaultValue=0, historySize=0, cellWidth=1 ):
		EmulatedMemory.__init__(self,ghidraProgram,addressWidth,cellWidth,defaultValue,historySize)
		self.readByte = self.read
		self.readWord = self.read
		self.readDword = self.read
		self.readQword = self.read
		self.writeByte = self.write
		self.writeWord = self.write
		self.writeDword = self.write
		self.writeQword = self.write
		self.getByte = self.getMemory
		self.getWord = self.getMemory
		self.getDword = self.getMemory
		self.getQword = self.getMemory
		self.setByte = self.setMemory
		self.setWord = self.setMemory
		self.setDword = self.setMemory
		self.setQword = self.setMemory
		
	def setByteWidth(self,byteWidth):
		pass
		