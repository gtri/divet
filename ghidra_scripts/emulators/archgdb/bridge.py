import subprocess

from javax.swing import JFrame
from javax.swing import JPanel


class Bridge:
	def __init__(self, ghidraState):
		self.gdb = subprocess.Popen("gdb",stderr=subprocess.STDOUT,stdout=subprocess.PIPE,stdin=subprocess.PIPE)
		self._read_until_prompt(True)
		
		#Initial Register state to reset to
		self.initState = None
		
		#
		#Calculate memory information
		#
		ghidraProgram = ghidraState.getCurrentProgram()
		ghidraLanguage = ghidraProgram.getLanguage()
		addressFactory = ghidraLanguage.getAddressFactory()
		
		#Figure out the address width
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
		
		if addressWidth % 4:
			self.addressFormat = "%%0%dX" % ((addressWidth/4 + 1))
		else:
			self.addressFormat = "%%0%dX" % (addressWidth/4)		
		self.byteWidth = 4
		self.addressMax = maxAddress
		self.program = ghidraProgram
	
	def __del__(self):
		print "__del__"
		self.gdb.terminate()
	
	def _read_until_prompt(self,ignore=False):
		if not ignore:
			output = []
		line = ""
		while True:
			line = line + self.gdb.stdout.read(1)
			if line == "(gdb) ":
				break
			elif line[-1] == "\n":
				line = line.strip()
				if ignore:
					print "%s\n" % line
				else:
					output.append(line)
				line = ""
		if not ignore:
			return output
	
	def _read_register_value(self,valuestr):
		#TODO: not all register types are supported for setting and reading values
		#So, they get filtered here.  This should be fixed
		try:
			value = int(valuestr,16)
		except ValueError:
			value = None
		return value
	
	def setTarget(self,path):
		self.gdb.stdin.write("target remote %s\n" % path)
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		self.initState = self.getState()
		
	#
	#Registers Interface
	#
	def getRegister(self,name):
		self.gdb.stdin.write("p/x $%s\n" % name)
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		value = self._read_register_value( output[0].split("=")[1].strip() )
		return value, 0
		
	def setRegister(self,name,value):
		self.gdb.stdin.write("set $%s=0x%X\n" % (name,value))
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		
	def getRegistersDefinition(self):
		self.gdb.stdin.write("maint print reggroup\n")
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		catNames = []
		for line in output[1:]:
			#print "[!] %s" % line
			items = [x for x in  line.split(" ") if len(x)]
			catNames.append(items[0])
		regDef = []
		for catName in catNames:
			if catName.lower() in ["all","save","restore"]:
				continue
			self.gdb.stdin.write("info registers %s\n" % catName)
			self.gdb.stdin.flush()
			output = self._read_until_prompt(False)
			regs = []
			for line in output:
				#print "[!!] %s" % line
				items = [x for x in line.split(" ") if len(x)]
				value = self._read_register_value(items[1])
				if value != None:
					regs.append([items[0],items[0],32])
			if len(regs):
				regDef.append([catName,regs])
		return regDef
		
	def reset(self):
		if self.initState != None:
			self.setState(self.initState)
		
	def getProgramCounter(self):
		return self.getRegister("pc")[0]
		
	def getStackPointerName(self):
		return "sp"
	
	def getState(self):
		self.gdb.stdin.write("info registers all\n")
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		state = []
		for line in output:
			items = [x for x in line.split(" ") if len(x)]
			name = items[0]
			value = self._read_register_value(items[1])
			if value != None:
				state.append(name)
				state.append("%X" % value)
		return ":".join(state)
	
	def setState(self,state):
		items = state.split(":")
		for i in xrange(len(items)/2):
			name = items[2*i]
			value = int(items[(2*i)+1],16)
			self.setRegister(name,value)
		
	#
	# CPU Interface
	#
	def getSignals(self):
		self.gdb.stdin.write("info signals\n")
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		signalNames = []
		for line in output[2:]:
			if not len(line.strip()):
				continue
			items = [x for x in line.split(" ") if len(x)]
			signalNames.append(items[0])
		return signalNames
		
	def signal(self,signalName):
		self.gdb.stdin.write("signal %s\n" % signalName)
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		
	def step(self):
		self.gdb.stdin.write("si\n")
		self.gdb.stdin.flush()
		self._read_until_prompt(True)

	#
	# EmulatedMemory Interface
	#
	def clear(self):
		pass
		
	def addBank(self,name,start,end,activate=False,default=False):
		pass
			
	def activateBank(self,name,activate=True):
		pass
	
	def getBanks(self):
		return ["MEM"]
			
	def setDefaultValue(self, value):
		pass
	
	def getDefaultValue(self):
		return 0
	
	def setLogger(self,logger):
		pass
	
	def startStepRecord(self):
		pass
		
	def getStepRecord(self):
		return []
	
	def getStepRecordSize(self):
		return 0

	def getRecordString(self,accessRecord):
		return ""
	
	def setTaint(self, address, taint, bankName=None):
		pass
		
	def getTaint(self, address, bankName=None):
		return 0
	
	def isTainted(self, address, bankName=None):
		return False
			
	def isManuallyTainted(self,address,bankName=None):
		return False
		
	def setReadValues(self, address, values, bankName=None):
		pass
		
	def getReadValues(self, address, bankName=None):
		return []
			
	def getReadValuesString(self, address, bankName=None):
		return ""
		
	def setStoredValue(self, address, value, bankName=None):
		if self.byteWidth == 1:
			self.writeByte(address,value,bankName)
		elif self.byteWidth == 2:
			self.writeWord(address,value,bankName)
		elif self.byteWidth == 4:
			self.writeDword(address,value,bankName)[0]
		elif self.byteWidth == 8:
			self.writeQword(address,value,bankName)[0]
		else:
			raise NotImplementedError,"byteWidth needs to be 1,2,4,or 8"
	
	def getStoredValue(self, address, bankName=None):
		if self.byteWidth == 1:
			value = self.readByte(address,bankName)[0]
		elif self.byteWidth == 2:
			value = self.readWord(address,bankName)[0]
		elif self.byteWidth == 4:
			value = self.readDword(address,bankName)[0]
		elif self.byteWidth == 8:
			value = self.readQword(address,bankName)[0]
		else:
			raise NotImplementedError,"byteWidth needs to be 1,2,4,or 8"		
		return value
			
	def getStoredValueString(self, address, bankName=None):
		return ""
		
	def setMutable(self, address, mutable, bankName=None):
		pass
	
	def isMutable(self, address, bankName=None):
		return True
	
	def getCurrentValueString(self, address, bankName=None):
		return self.getValueString(self.getStoredValue(address,bankName))
	
	def getValueString(self, value):
		return self.cellFormat % value
	
	def getAddressString(self, address, prefix=False):
		address = address & self.addressMax
		if prefix:
			return "0x%s" % (self.addressFormat % address)
		else:
			return self.addressFormat % address
	
	def getSymbolName(self, address):
		name = ""
		if self.program != None:
			address = address & self.addressMax
			addressStr = self.getAddressString(address, prefix=True)
			jaddr = self.program.getAddressFactory().getAddress(addressStr)
			symbol = self.program.getSymbolTable().getPrimarySymbol(jaddr)
			if symbol != None:
				name = symbol.getName()
		return name
	
	def getData(self, address):
		if self.program != None:
			address = address & self.addressMax
			addressStr = self.getAddressString(address, prefix=True)
			jaddr = self.program.getAddressFactory().getAddress(addressStr)
			data = self.program.getListing().getDataAt(jaddr)
			if data != None:
				return data
		return None
	
	def getDataType(self, address):
		data = self.getData(address)
		if data is not None:
			return data.getDataType()
		return "?"
	
	def reset(self):
		pass

	def read(self, address, bankName=None):
		raise NotImplementedError,"GDB does not support widthless storing"
		
	def write(self, address, value, taint, bankName=None):
		raise NotImplementedError,"GDB does not support widthless storing"
		
	def undoStep(self):
		return False
	
	#
	# Script Access Functions
	#
	def getMemory(self, address, bankName=None):
		raise NotImplementedError,"GDB does not support widthless reading"
	
	def setMemory(self, address, value, taint, bankName=None):
		raise NotImplementedError,"GDB does not support widthless writing"		
		
	#
	# Save and Load State
	#
	def saveState(self, fp, includeHistory=False):
		pass
		
	def loadState(self, fp):
		pass

	def setByteWidth(self,byteWidth):
		self.byteWidth = byteWidth
		self.cellFormat = "%%0%dX" % (byteWidth*2)

	#
	# Additional memory convience Functions
	#
	def readByte(self, address, bankName=None):
		self.setByteWidth(1)
		self.gdb.stdin.write("p/x {char}0x%X\n" % (address))
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		if "=" not in output[0]:
			return 0,0
		return int(output[0].split("=")[1],16),0
		
	def readWord(self, address, bankName=None):
		self.setByteWidth(2)
		self.gdb.stdin.write("p/x {short}0x%X\n" % (address))
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		if "=" not in output[0]:
			return 0,0
		return int(output[0].split("=")[1],16),0
		
	def readDword(self, address, bankName=None):
		self.setByteWidth(4)
		self.gdb.stdin.write("p/x {int}0x%X\n" % (address))
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		if "=" not in output[0]:
			return 0,0
		return int(output[0].split("=")[1],16),0
		
	def readQword(self, address, bankName=None):
		self.setByteWidth(8)
		self.gdb.stdin.write("p/x {long long}0x%X\n" % (address))
		self.gdb.stdin.flush()
		output = self._read_until_prompt(False)
		if "=" not in output[0]:
			return 0,0
		return int(output[0].split("=")[1],16),0

	def writeByte(self, address, value, tainted, bankName=None):
		self.setByteWidth(1)
		self.gdb.stdin.write("set {char}0x%X=0x%X\n" % (address,value))
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		
	def writeWord(self, address, value, tainted, bankName=None):
		self.setByteWidth(2)
		self.gdb.stdin.write("set {short}0x%X=0x%X\n" % (address,value))
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		
	def writeDword(self, address, value, tainted, bankName=None):
		self.setByteWidth(4)
		self.gdb.stdin.write("set {int}0x%X=0x%X\n" % (address,value))
		self.gdb.stdin.flush()
		self._read_until_prompt(True)
		
	def writeQword(self, address, value, tainted, bankName=None):
		self.setByteWidth(8)
		self.gdb.stdin.write("set {long long}0x%X=0x%X\n" % (address,value))
		self.gdb.stdin.flush()
		self._read_until_prompt(True)

	def getByte(self, address, bankName=None):
		return self.readByte(address,bankName)
		
	def getWord(self, address, bankName=None):
		return self.readWord(address,bankName)
		
	def getDword(self, address, bankName=None):
		return self.readDword(address,bankName)
				
	def getQword(self, address, bankName=None):
		return self.readQword(address,bankName)
		
	def setByte(self, address, value, tainted, bankName=None):
		return self.writeByte(address,value,tainted,bankName)

	def setWord(self, address, value, tainted, bankName=None):
		return self.writeWord(address,value,tainted,bankName)
	
	def setDword(self, address, value, tainted, bankName=None):
		return self.writeDword(address,value,tainted,bankName)
	
	def setQword(self, address, value, tainted, bankName=None):
		return self.writeQword(address,value,tainted,bankName)
		
	def setByteReadValues(self, address, values, bankName=None):
		pass
		
	def setWordReadValues(self, address, values, bankName=None):
		pass
		
	def setDwordReadValues(self, address, values, bankName=None):
		pass
		
	def setQwordReadValues(self, address, values, bankName=None):
		pass
		
	def getByteReadValues(self, address, bankName=None):
		return []
		
	def getWordReadValues(self, address, bankName=None):
		return []
		
	def getDwordReadValues(self, address, bankName=None):
		return []
		
	def getQwordReadValues(self, address, bankName=None):
		return []


if __name__ == "__main__":
	b = Bridge()
	b.setTarget("localhost:2323")
	#print b.getRegisterDefinition()
	print b.getState()