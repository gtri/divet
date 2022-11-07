from ghidra.app.emulator.state import DumpMiscState
from ghidra.program.model.lang import RegisterValue
import jarray
import struct
	
class Registers:
	def __init__(self,ghidraState):
		ghidraProgram = ghidraState.getCurrentProgram()
		self.ghidraLanguage = ghidraProgram.getLanguage()
		ghidraRegisters = self.ghidraLanguage.getRegisters()
		addressFactory = self.ghidraLanguage.getAddressFactory()
		addressSpace = addressFactory.getRegisterSpace()
		self.space = addressSpace

		self.pcReg = self.ghidraLanguage.getProgramCounter()
		self.regLookupByName = {}
		self.regStorage = []
		self.regDef = []
		
		regGroups = {}
		for ghidraReg in ghidraRegisters:
			group = ghidraReg.getGroup()
			displayName = ghidraReg.getName()
			bitLength = ghidraReg.getBitLength()
			byteLength = ghidraReg.getMinimumByteSize()
			byteOffset = ghidraReg.getOffset()
			bitOffset = ghidraReg.getLeastSignificantBit()
			parent = ghidraReg.getParentRegister()
			
			if group == None:
				group = "General"
			
			if displayName != None and len(displayName):
				name = displayName.lower()
				
				bitMask = 0
				for i in xrange(bitLength):
					bitMask = (bitMask<<1)|1
				bitMask = bitMask << bitOffset
				
				regInfo = [byteOffset,bitOffset,byteLength,bitLength,bitMask,ghidraReg]
				
				#Find the storage info by name/alias
				self.regLookupByName[name] = regInfo
				self.regLookupByName[displayName] = regInfo
				for alias in ghidraReg.getAliases():
					self.regLookupByName[alias] = regInfo
				
				#Added the register to a group for display/editing
				if parent == None and not ghidraReg.isHidden():
					if not regGroups.has_key(group):
						regGroups[group] = {}
					regGroups[group][byteOffset] = [name,displayName,bitLength]
			
			#Added to the flat(ish) storage structure
			inserted = False
			newStorageNode = [byteOffset,[0 for b in xrange(byteLength)],[0 for b in xrange(byteLength)]]
			for i in xrange(len(self.regStorage)):
				storageOffset, storageBytes, storageTaint = self.regStorage[i]
				if byteOffset == storageOffset:
					inserted = True
					if byteLength > len(storageBytes):
						self.regStorage[i] = newStorageNode
					else:
						break
				elif byteOffset < storageOffset:
					self.regStorage.insert(i,newStorageNode)
					inserted = True
					break
			if not inserted:
				self.regStorage.append(newStorageNode)
		
		#Go through regGroups and create regDef
		groups = regGroups.keys()
		groups.sort()
		for group in groups:
			catDef = []
			offsets = regGroups[group].keys()
			offsets.sort()
			for offset in offsets:
				catDef.append(regGroups[group][offset])
			self.regDef.append([group,catDef])

	def getRegisterByOffset(self,offset,size):
		bytes = []
		taint = 0
		for i in xrange(len(self.regStorage)):
			storageOffset, storageData, storageTaint = self.regStorage[i]
			if storageOffset <= offset and offset+size <= storageOffset + len(storageData):
				start = offset - storageOffset
				for i in xrange(size):
					bytes.append(storageData[start+i])
					taint = taint | storageTaint[start+i] 
				break
		return bytes, taint

	def setRegisterByOffset(self,offset,size,bytes,taint):
		for i in xrange(len(self.regStorage)):
			storageOffset, storageData, storageTaint = self.regStorage[i]
			if storageOffset <= offset and offset+size <= storageOffset + len(storageData):
				start = offset - storageOffset
				for i in xrange(size):
					storageData[start+i] = bytes[i]
					storageTaint[start+i] = taint
				break

	def getRegister(self,name,mask=True):
		byteOffset,bitOffset,byteSize,bitSize,bitMask,ghidraReg = self.regLookupByName[name]
		bytes, taint = self.getRegisterByOffset(byteOffset,byteSize)
		value = 0
		if self.ghidraLanguage.isBigEndian() or ghidraReg.isProcessorContext():
			for i in xrange(byteSize):
				value = (value << 8) | bytes[i]
		else:
			for i in xrange(byteSize):
				value = (value>>8) | (bytes[i]<<((byteSize-1)*8))
		if bitOffset and mask:
			value = (value & bitMask) >> bitOffset
		return value, taint

	def setRegister(self,name,value,taint):
		byteOffset,bitOffset,byteSize,bitSize,bitMask,ghidraReg = self.regLookupByName[name]
		bytes = []
		if bitOffset:
			currentValue, currentTaint = self.getRegister(name,mask=False)
			value = (currentValue & (~bitMask)) | ((value << bitOffset) & bitMask)
			taint = taint | currentTaint
		if self.ghidraLanguage.isBigEndian() or ghidraReg.isProcessorContext():
			for i in xrange(byteSize):
				byte = int((value>>((byteSize-1-i)*8))&0xFF)
				bytes.append(byte)
		else:
			for i in xrange(byteSize):
				byte = int((value>>(i*8))&0xFF)
				bytes.append(byte)
		self.setRegisterByOffset(byteOffset,byteSize,bytes,taint)

	def getRegisterValue(self,name):
		byteOffset,bitOffset,byteSize,bitSize,bitMask,ghidraReg = self.regLookupByName[name]
		value, taint = self.getRegister(name)
		regValue = RegisterValue(ghidraReg,long(value))
		return regValue

	def setRegisterValue(self, name, regValue, taint):
		value = regValue.getUnsignedValueIgnoreMask()
		self.setRegister(name, value, taint)

	def getRegistersDefinition(self):
		return self.regDef

	def reset(self):
		for i in xrange(len(self.regStorage)):
			offset, data, taint = self.regStorage[i]
			self.regStorage[i] = [offset,[0 for b in data],[0 for b in taint]]

	def getProgramCounter(self):
		if self.pcReg == None:
			return 0
		else:
			value, taint = self.getRegister(self.pcReg.getName().lower())
			return value

	def getStackPointerName(self):
		return None
	
	def getState(self):
		state = ":".join([repr(node).replace(" ","") for node in self.regStorage])
		return state

	def setState(self,state):
		self.regStorage = []
		for node in state.split(":"):
			self.regStorage.append(eval(node))
		#self.regStorage = eval(state)
