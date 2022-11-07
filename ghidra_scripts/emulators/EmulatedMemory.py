MUTABLE = 0
TAINTCFG = 1
READ_VALUES = 2
READ_IDX = 3
STORED_VALUE = 4
STORED_TAINT = 5
def newMemoryCell():
	return [True, False, [], 0, None, 0]

BANKNAME    = 0
BANKSTART   = 1
BANKEND     = 2
BANKACTIVE  = 3
BANKCELLS   = 4
def newMemoryBank(name,start,end):
	return [name,start,end,False,{}]

AREAD    = 0b0001
AREADIDX = 0b0010
AWRITE   = 0b0100
AUNDO    = 0b1000
	
#from ghidra.program.flatapi import FlatProgramAPI

class EmulatedMemory:
	def __init__(self, ghidraProgram=None, addressBitWidth=16, cellByteWidth=1, defaultValue=0, historySize=0):
		self.program = ghidraProgram
		self.logger = None
		
		if addressBitWidth % 4:
			self.addressFormat = "%%0%dX" % ((addressBitWidth/4 + 1))
		else:
			self.addressFormat = "%%0%dX" % (addressBitWidth/4)
		self.addressMax = (1 << addressBitWidth) - 1
		
		if cellByteWidth not in [1, 2, 4, 8]:
			raise NotImplementedError, "cellByteWidth must be 1, 2, 4, or 8"
		self.cellFormat = "%%0%dX" % (cellByteWidth*2)
		self.cellMax = (1 << cellByteWidth*8) - 1
		self.byteWidth = cellByteWidth
		
		self.defaultValue = defaultValue & self.cellMax
		self.historySize = historySize
		self.history = []
		self.historySteps = []
		self.banks = []
		self.addBank("MEM",0,self.addressMax,activate=True,default=True)
		self.activateBank("MEM")

	def clear(self):
		self.history = []
		self.historySteps = []
		for i in xrange(len(self.banks)):
			self.banks[i][BANKCELLS] = {}
			
	def addBank(self,name,start,end,activate=False,default=False):
		bankNames = [bank[BANKNAME] for bank in self.banks]
		if name in bankNames:
			del self.banks[bankNames.index(name)]
		if default:
			self.banks = self.banks + [newMemoryBank(name,start,end)]
		else:
			self.banks = [newMemoryBank(name,start,end)] + self.banks
		if activate:
			self.activateBank(name)
			
	def activateBank(self,name,activate=True):
		for bank in self.banks:
			if bank[BANKNAME] == name:
				bank[BANKACTIVE] = activate
				break
	
	def getBanks(self):
		bankNames = [bank[BANKNAME] for bank in self.banks]
		bankNames.reverse()
		return bankNames
	
	def _getCells(self,address,bankName=None,returnName=False):
		name = None
		cells = None
		
		if bankName == None:
			#Need to dynamically locate the correct bank
			for bank in self.banks:
				if bank[BANKACTIVE] and address >= bank[BANKSTART] and address < bank[BANKEND]:
					name = bank[BANKNAME]
					cells = bank[BANKCELLS]
					break
			if cells == None:
				if not len(self.banks) or not self.banks[-1][BANKACTIVE]:
					raise ValueError,"Could not determine a memory bank"
				#No bank could be found.  We assume the address expects mirroring (wrap-around)
				#We'll only do this for the default bank
				bank = self.banks[-1]
				cells = bank[BANKCELLS]
				address = address % bank[BANKEND]
				name = bank[BANKNAME]
				if address < bank[BANKSTART]:
					raise ValueError,"Could not use default memory bank"
		else:
			#The bankName was explicitly specified, so we don't care if the
			#the bank is active, or if the address is too large for it - we'll try mirring (wrap-around)
			for bank in self.banks:
				if bankName == bank[BANKNAME]:
					cells = bank[BANKCELLS]
					address = address % bank[BANKEND]
					name = bank[BANKNAME]
					if address < bank[BANKSTART]:
						raise ValueError,"Could not use memory bank %s" % bankName
					break
			if cells == None:
				raise ValueError,"Could not find memory bank %s" % bankName

		if returnName:
			return cells,address,name
		else:
			return cells,address
		
	def setDefaultValue(self, value):
		self.defaultValue = value & self.cellMax
	
	def getDefaultValue(self):
		return self.defaultValue
	
	def setLogger(self,logger):
		self.logger = logger
	
	def startStepRecord(self):
		self.historySteps.append(len(self.history))
		
	def getStepRecord(self):
		if not len(self.historySteps):
			return []
		else:
			return self.history[self.historySteps[-1]:]
		
	def getStepRecordSize(self):
		if not len(self.historySteps):
			return 0
		else:
			return len(self.history) - self.historySteps[-1]
	
	def getRecordString(self,accessRecord):
		bankName, accessType, address, value, taint = accessRecord[:5]
		addrStr = self.getAddressString(address)
		name  = self.getSymbolName(address)
		valueStr = self.getValueString(value)
		if accessType in [AREAD,AREADIDX]:
			if taint:
				accessStr = "%s[%s] %s =R=> %s [T]\n" % (bankName, addrStr, name, valueStr)
			else:
				accessStr = "%s[%s] %s =R=> %s\n" % (bankName, addrStr, name, valueStr)
		elif accessType == AWRITE:
			if taint:
				accessStr = "%s[%s] %s <=W= %s [T]\n" % (bankName, addrStr, name, valueStr)
			else:
				accessStr = "%s[%s] %s <=W= %s\n" % (bankName, addrStr, name, valueStr)
		else:
			accessStr = "?"
		return accessStr
	
	def _checkHistoryOverflow(self):
		if not self.historySize:
			return
		if len(self.history) <= self.historySize:
			return
		if not len(self.historySteps):
			raise RuntimeError,"Emulated Memory History is too small to support a single step"
		self.history = self.history[self.historySteps[0]:]
		self.historySteps = [historyIdx-self.historySteps[0] for historyIdx in self.historySteps[1:]]
		
	def setTaint(self, address, taint, bankName=None):
		cells, address = self._getCells(address,bankName)
			
		#If we aren't tracking this address at all, add it to cells
		if not cells.has_key(address):
			cell = newMemoryCell()
			cells[address] = cell
		else:
			cell = cells[address]
		if taint:
			cell[TAINTCFG] = True
		else:
			cell[TAINTCFG] = False
		cell[STORED_TAINT] = int(taint)
	
	def getTaint(self, address, bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
		except KeyError:
			return 0
			
		taint = cell[STORED_TAINT]
		if not taint and cell[TAINTCFG]:
			return 1
		else:
			return taint
	
	def isTainted(self, address, bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
		except KeyError:
			return False

		return cell[TAINTCFG] or bool(cell[STORED_TAINT])
			
	def isManuallyTainted(self,address,bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
		except KeyError:
			return False		
		return cell[TAINTCFG]
		
		
	def setReadValues(self, address, values, bankName=None):
		cells, address = self._getCells(address,bankName)
		#If we aren't tracking this address at all, add it to cells
		if not cells.has_key(address):
			cell = newMemoryCell()
			cells[address] = cell
		else:
			cell = cells[address]
		cell[READ_VALUES] = [value & self.cellMax for value in values]
		cell[READ_IDX] = 0
		
	def getReadValues(self, address, bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
			return cell[READ_VALUES]
		except KeyError:
			return []
			
	def getReadValuesString(self, address, bankName=None):
		return ", ".join([self.getValueString(value) for value in self.getReadValues(address,bankName)])
	
	def setStoredValue(self, address, value, bankName=None):
		cells, address = self._getCells(address,bankName)
		value = value & self.cellMax
		if not cells.has_key(address):
			cell = newMemoryCell()
			cells[address] = cell
		else:
			cell = cells[address]
		if cell[TAINTCFG]: taint = 1
		else: taint = 0
		if self.logger != None:
			self.logger.logComment("User Interface Write")
		self.write(address,value,taint)
	
	def getStoredValue(self, address, bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
			return cell[STORED_VALUE]
		except KeyError:
			return None
			
	def getStoredValueString(self, address, bankName=None):
		value = self.getStoredValue(address,bankName)
		if value == None:
			return ""
		else:
			return self.getValueString(value)
		
	def setMutable(self, address, mutable, bankName=None):
		cells, address = self._getCells(address,bankName)
		#If we aren't tracking this address at all, add it to cells
		if not cells.has_key(address):
			cell = newMemoryCell()
			cells[address] = cell
		else:
			cell = cells[address]
		if mutable:
			cell[MUTABLE] = True
		else:
			cell[MUTABLE] = False
	
	def isMutable(self, address, bankName=None):
		cells, address = self._getCells(address,bankName)
		try:
			cell = cells[address]
			return cell[MUTABLE]
		except KeyError:
			return True
	
	def getCurrentValueString(self, address, bankName=None):
		bankName, accessType, address, value, taint = self._read(address,bankName=bankName)
		return self.getValueString(value)
	
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
		for bank in self.banks:
			cells = bank[BANKCELLS]
			for address in cells:
				cell = cells[address]
				cell[READ_IDX] = 0
				cell[STORED_VALUE] = None
				cell[STORED_TAINT] = 0

	def read(self, address, bankName=None):
		bankName, accessType, address, value, taint = self._read(address,readInc=True,bankName=bankName)
		
		#Record the History
		self.history.append([bankName, accessType, address, value, taint])
		self._checkHistoryOverflow()
		if self.logger != None:
			self.logger.logMemoryAccess(bankName,AREAD,address,value,taint)
		return value, taint
	
	def _read(self, address, readInc=False, bankName=None):
		cells, address, bankName = self._getCells(address,bankName,returnName=True)
		
		accessType = AREAD
		value = None
		taint = None
		if cells.has_key(address):
			cell = cells[address]
			if cell[TAINTCFG]: taint = 1
			else: taint = 0
			read_values = cell[READ_VALUES] 

			#Try a previously written value
			if cell[MUTABLE] and cell[STORED_VALUE] != None:
				value = cell[STORED_VALUE]
				taint = cell[STORED_TAINT]
			
			#Try a specified Read Values
			elif len(read_values):
				read_idx = cell[READ_IDX]
				value = read_values[read_idx]
				if cell[TAINTCFG]: taint = 1
				else: taint = 0
				if readInc:
					read_idx = (read_idx + 1) % len(read_values)
					cell[READ_IDX] = read_idx
				accessType = AREADIDX
				
		else:
			#Cell defaults to non-tainted if it isn't being tracked
			taint = 0

		#Try a value in the ghidra database
		if value == None and self.program != None:
			mem = self.program.getMemory()
			jaddr = self.program.getAddressFactory().getAddress("0x%X" % (address))
			if self.byteWidth == 1:
				try:
					value = (mem.getByte(jaddr) + 0x100) & 0xFF
				except: #I'm not sure of the correct exception - maybe mem.MemoryAccessException:
					pass
			elif self.byteWidth == 2:
				try:
					value = (mem.getShort(jaddr) + 0x10000) & 0xFFFF
				except: #I'm not sure of the correct exception - maybe mem.MemoryAccessException:
					pass
			elif self.byteWidth == 4:
				try:
					value = (mem.getInt(jaddr) + 0x100000000L) & 0xFFFFFFFF
				except: #I'm not sure of the correct exception - maybe mem.MemoryAccessException:
					pass
			elif self.byteWidth == 8:
				try:
					value = (mem.getLong(jaddr) + 0x10000000000000000L) & 0xFFFFFFFFFFFFFFFF
				except: #I'm not sure of the correct exception - maybe mem.MemoryAccessException:
					pass
			else:
				raise NotImplementedError,"Cell byteWidth must be 1, 2, 4, or 8"
		
		#Drop back the the default value
		if value == None:
			value = self.defaultValue
		
		return bankName, accessType, address, value, taint
	
	def write(self, address, value, taint, bankName=None):
		bankName, address, prevValue, prevTaint = self._write(address, value, taint, bankName)
		
		#Record the History
		self.history.append([bankName, AWRITE, address, value, taint, prevValue, prevTaint])
		if self.logger != None:
			self.logger.logMemoryAccess(bankName,AWRITE,address,value,taint)
		self._checkHistoryOverflow()
	
	def _write(self, address, value, taint, bankName):
		cells, address, bankName = self._getCells(address,bankName,returnName=True)
		value = value & self.cellMax
		taint = int(taint)
		
		#If we aren't tracking this address at all, add it to cells
		if not cells.has_key(address):
			cell = newMemoryCell()
			cells[address] = cell
		else:
			cell = cells[address]
		
		prevValue = cell[STORED_VALUE]
		prevTaint = cell[STORED_TAINT]
			
		cell[STORED_VALUE] = value
		cell[STORED_TAINT] = taint
		
		return bankName, address, prevValue, prevTaint
		
	def undoStep(self):
		if not len(self.historySteps):
			return False
		count = self.getStepRecordSize()
		if len(self.history) < count:
			return False
		for i in xrange(count):
			if self.logger != None:
				self.logger.logMemoryUndoAccess(*self.history[-1][:5])
			self._undoAccess(self.history[-1])
			self.history = self.history[:-1]
		self.historySteps = self.historySteps[:-1]
		return True

	def _undoAccess(self,record):
		bankName, atype, address, value, taint = record[:5]
		cells, address = self._getCells(address,bankName)
		prevValue = None
		prevTaint = None
		
		#We only have stuff to undo if the cell is
		#being tracked
		if cells.has_key(address):
			cell = cells[address]
			if atype == AREADIDX:
				#Reads only need to be undone if the READ_VALUES
				#are being used.  Then just decrement the index
				read_values = cell[READ_VALUES]
				if len(read_values):
					read_idx = cell[READ_IDX]-1
					if read_idx < 0:
						read_idx = len(read_values)-1
					cell[READ_IDX] = read_idx
					prevValue = read_values[read_idx]
					if cell[TAINTCFG]: prevTaint = 1
					else: prevTaint = 0
					
			elif atype == AWRITE:
				prevValue, prevTaint = record[5:7]
				cell[STORED_VALUE] = prevValue
				cell[STORED_TAINT] = prevTaint
			
		return True

	#
	# Script Access Functions
	#
	def getMemory(self, address, bankName=None):
		#We intentionally call self._read here to avoid logging the access
		bankName, accessType, address, value, taint  = self._read(address,bankName=bankName)
		return value, taint
		
	def setMemory(self, address, value, taint, bankName=None):
		if self.logger != None:
			self.logger.logComment("Script Write")
		self.write(address,value,taint,bankName)
		
		
	#
	# Save and Load State
	#
	def saveState(self, fp, includeHistory=False):
		fp.write("[MemoryState]\n")
		fp.write("addressFormat: %s\n" % self.addressFormat)
		fp.write("addressMax: %X\n" % self.addressMax)
		fp.write("cellFormat: %s\n" % self.cellFormat)
		fp.write("cellMax: %X\n" % self.cellMax)
		fp.write("byteWidth: %d\n" % self.byteWidth)
		fp.write("defaultValue: %X\n" % self.defaultValue)
		fp.write("historySize: %d\n" % self.historySize)

		for bi in xrange(len(self.banks)):
			bankName, start, end, active, cells = self.banks[bi]
			if active: activeStr = "T"
			else: activeStr = "F"
			fp.write("bank[%d]: %s, %X, %X, %s\n" % (bi, bankName, start, end, activeStr))
			for address in cells:
				mutable, taintcfg, read_values, read_idx, stored_value, stored_taint = cells[address]
				if mutable: mutableStr = "T"
				else: mustableStr = "F"
				if taintcfg: taintcfgStr = "T"
				else: taintcfgStr = "F"
				if stored_value == None: stored_valueStr = "N"
				else: stored_valueStr = "%X" % stored_value
				read_valuesStr = repr(["%X" % x for x in read_values])	
				fp.write("cell[%d][%X]: %s, %s, %s, %d, %s, %X\n" % (bi,address,mutableStr,taintcfgStr,read_valuesStr,read_idx,stored_valueStr,stored_taint))
		
		if includeHistory:
			for i in xrange(len(self.history)):
				bankName, accessType, address, value, taint = self.history[i]
				fp.write("history[%d]: %s, %X, %X, %X, %X\n" % (i,bankName,accessType,address,value,taint))
			for si in xrange(len(self.historySteps)):
				for i in xrange(len(self.historySteps[si])):
					bankName, accessType, address, value, taint = self.historySteps[si][i]
					fp.write("historySteps[%d][%d]: %s, %X, %X, %X, %X\n" % (si,i,bankName,accessType,address,value,taint))
		
	def loadState(self, fp):
		self.history = []
		self.historySteps = []
		self.banks = []
		
		fp.seek(0)
		ready = False
		while True:
			line = fp.readline()
			if not len(line):
				break
			line = line.strip()
			if not len(line):
				continue
			if line[0] == "[":
				if line.strip().lower() == "[memorystate]":
					ready = True
				elif ready:
					break #Finished read section
				else:
					ready = False
					
			if ready:
				items = [x.strip() for x in line.split(":")]
				label = items[0].lower()
				if label == "addressformat":
					self.addressFormat = items[1]
				elif label == "addressmax":
					self.addressMax = int(items[1],16)
				elif label == "cellformat":
					self.cellFormat = items[1]
				elif label == "cellmax":
					self.cellMax = int(items[1],16)
				elif label == "bytewidth":
					self.byteWidth = int(items[1],10)
				elif label == "defaultvalue":
					self.defaultValue = int(items[1],16)
				elif label == "historySize":
					self.historySize = int(items[1],10)
				elif label[:5] == "bank[" and label[-1] == "]":
					bankIdx = int(label[5:-1],10)
					while len(self.banks) < (bankIdx+1):
						self.banks.append(newMemoryBank(None,0,0))
					values = [x.strip() for x in items[1].split(",")]
					self.banks[bankIdx][BANKNAME]   = values[0]
					self.banks[bankIdx][BANKSTART]  = int(values[1],16)
					self.banks[bankIdx][BANKEND]    = int(values[2],16)
					self.banks[bankIdx][BANKACTIVE] = values[3].upper() == "T"
				elif label[:5] == "cell[" and label[-1] == "]":
					try:
						bankIdx = int(label[5:label.index("]")],10)
					except ValueError:
						print "Unable to parse bank index in: %s" % repr(line)
						continue
					try:
						address = int(label[ 6+label[5:].index("[") : -1],16)
					except ValueError:
						print "Unable to parse cell address in: %s" % line
						print "int(%s,16)" % label[ 6+label[5:].index("[") : -1]
						continue
					while len(self.banks) < (bankIdx+1):
						self.banks.append(newMemoryBank(None,0,0))
					cells = self.banks[bankIdx][BANKCELLS]
					cells[address] = newMemoryCell()
					cell = cells[address]
					values = [x.strip() for x in items[1].split(",")]
					cell[MUTABLE]     = values[0].upper() == "T"
					cell[TAINTCFG]    = values[1].upper() == "T"
					if values[2][0] != "[":
						print "Unable to parse read values in: %s" % line
						continue
					if values[2][-1] == "]" and len(values[2][1:-1].strip()) != 0:
						valuesIdx = 2
						try:
							values[2] = values[2][1:]
							while values[valuesIdx][-1] != "]":
								cell[READ_VALUES].append( int(values[valuesIdx],16) )
								valuesIdx = valuesIdx + 1
							cell[READ_VALUES].append( int(values[valuesIdx][:-1],16) )
							valuesIdx = valuesIdx + 1
						except ValueError:
							print "Unable to parse read values in: %s" % line
							break
					else:
						valuesIdx = 3
					cell[READ_IDX]     = int( values[valuesIdx], 10 )
					valuesIdx = valuesIdx + 1
					if values[valuesIdx].upper() == "N":
						cell[STORED_VALUE] = None
					else:
						cell[STORED_VALUE] = int( values[valuesIdx], 16 )
					valuesIdx = valuesIdx + 1
					cell[STORED_TAINT] = int( values[valuesIdx], 16 )
				elif label[:8] == "history[" and lable[-1] == "]":
					try:
						historyIdx = int(label[8:-1],10)
					except ValueError:
						print "Unabel to parse history index in: %s" % repr(line)
						continue
					while len(self.history) < (historyIdx+1):
						self.history.append([])
					values = [x.strip() for x in items[1].split(",")]
					bankName = values[0]
					accessType = int(values[1],16)
					address = int(values[2],16)
					value = int(values[3],16)
					taint = int(values[4],16)
					self.history[historyIdx] = [bankName,accessType,address,value,taint] 
				elif label[:13] == "historySteps[":
					try:
						stepIdx = int(label[13:label.index("]")],10)
					except ValueError:
						print "Unable to parse history step index in: %s" % repr(line)
						continue
					try:
						accessIdx = int(label[ 14+label[13:].index("[") : -1],10)
					except ValueError:
						print "Unable to parse history step access index in: %s" % line
						continue
					while len(self.historySteps) < (stepIdx+1):
						self.historySteps.append([])
					while len(self.historySteps[stepIdx]) < (accessIdx+1):
						self.historySteps[stepIdx].append([])
					values = [x.strip() for x in items[1].split(",")]
					bankName = values[0]
					accessType = int(values[1],16)
					address = int(values[2],16)
					value = int(values[3],16)
					taint = int(values[4],16)
					self.historySteps[stepIdx][accessIdx] = [bankName,accessType,address,value,taint]
				
		#Double list contents
		for i in xrange(len(self.banks)):
			if self.banks[i][BANKNAME] == None:
				raise ValueError,"Memory load state failed to intialize all memory banks"
		for i in xrange(len(self.history)):
			if len(self.history[i]) != 5:
				raise ValueError,"Memory load state failed to initialize current step history"
		for si in xrange(len(self.historySteps)):
			for i in xrange(len(self.historySteps[si])):
				if len(self.historySteps[si][i]) != 5:
					raise ValueError,"Memory load state failed to intialize full history"
