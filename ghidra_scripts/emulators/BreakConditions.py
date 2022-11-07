from EmulatedMemory import AREAD,AWRITE

BREAKTARGET_SINGLE = 0
BREAKTARGET_RANGE  = 1
BREAKTARGET_SET    = 2
BREAKTARGET_NULL   = 3
BREAKTARGET_STRINGS = ["SINGLE","RANGE","SET","NULL"]
RANGE_MIN = "MIN"
RANGE_MAX = "MAX"

BREAKACCESS_R   = 0
BREAKACCESS_W   = 1
BREAKACCESS_RW  = 2
BREAKACCESS_REG = 3
BREAKACCESS_BP  = 4
BREAKACCES_MEMTYPES = [BREAKACCESS_R,BREAKACCESS_W,BREAKACCESS_RW]
BREAKACCESS_STRINGS = ["R","W","RW","REG","BP"]

BREAKCOND_LT   = 0
BREAKCOND_LTEQ = 1
BREAKCOND_EQ   = 2
BREAKCOND_GTEQ = 3
BREAKCOND_GT   = 4
BREAKCOND_NEQ  = 5
BREAKCOND_STRINGS = ["<","<=","==",">=",">","!="]

BREAKVALUE_ANY = None

BREAKTAINTED_TAINTED   = 0
BREAKTAINTED_UNTAINTED = 1
BREAKTAINTED_ANY       = 2
BREAKTAINTED_STRINGS = ["T","U",""]

#Internal data indexes
ACCESS_TYPE  =  0
BANK_NAME    =  1
TARGET_TYPE  =  2
TARGET_VALUE =  3
COND         =  4
VALUE        =  5
TAINTED      =  6
ENABLED      =  7
TRIGGERED    =  8
SCRIPT       =  9
DESCRIPTION  = 10

class BreakConditions:
	def __init__(self,regs,mem,ghidraProgram=None):
		self.regs = regs
		self.mem = mem
		self.program = ghidraProgram
		self.conditions = []
		self.triggeredConditions = []
	
	#Central function for adding watch conditions.
	#Other convience functions that create the correct arguments may be more
	#useful.
	def addCondition(self,accessType,bankName,targetType,target,condition,value,tainted,description=None,enabled=True):
		#Validate accessType, and condition
		if accessType in BREAKACCES_MEMTYPES:
			if bankName != None and bankName not in self.mem.getBanks():
				raise ValueError,"bankName is invalid"
			fixedBankName = bankName
			if targetType == BREAKTARGET_SINGLE:
				fixedTarget = self._targetToAddress(target)
			elif targetType == BREAKTARGET_RANGE:
				err = False
				try:
					if len(target) != 2:
						err = True
				except TypeError:
					err = True
				if err:
					raise ValueError,"targetType BREAKTARGET_RANGE requires a target of length 2"
				fixedTarget = [self._targetToAddress(t,range=True) for t in target]
				if RANGE_MIN in fixedTarget and fixedTarget[0] != RANGE_MIN:
					raise ValueError,"target range can not end with minimum"
				if RANGE_MAX in fixedTarget and fixedTarget[1] != RANGE_MAX:
					raise ValueError,"target range can not begin with maximum"
			elif targetType == BREAKTARGET_SET:
				fixedTarget = [self._targetToAddress(t) for t in target]
			else:
				raise ValueError,"targetType is invalid" 
		elif accessType == BREAKACCESS_REG:
			fixedBankName = None
			if targetType == BREAKTARGET_SINGLE:
				fixedTarget = self._targetToRegister(target)
			elif targetType == BREAKTARGET_SET:
				fixedTarget = [self._targetToRegister(t) for t in target]
			else:
				raise ValueError,"targetType is invalid" 
		elif accessType == BREAKACCESS_BP:
			fixedBankName = None
			if targetType != BREAKTARGET_NULL:
				raise ValueError,"targetType is invalid"
			fixedTarget = None
		else:
			raise ValueError,"accessType is invalid"

		#Validate condition
		if condition not in [BREAKCOND_LT,BREAKCOND_LTEQ,BREAKCOND_EQ,BREAKCOND_GTEQ,BREAKCOND_GT,BREAKCOND_NEQ]:
				raise ValueError,"condition is not valid"

		#Validate value
		if type(value) == str:
			if value == "*":
				fixedValue = BREAKVALUE_ANY
			else:
				fixedValue = self._targetToAddress(value)
		elif type(value) == int:
			fixedValue = value
		elif value == BREAKVALUE_ANY:
			fixedValue = value
		else:
			raise ValueError,"value is not valid"
		
		#Validate tainted
		if tainted not in [BREAKTAINTED_TAINTED, BREAKTAINTED_UNTAINTED, BREAKTAINTED_ANY]:
			raise ValueError,"tainted flag is not valid"
		
		#Validate enabled:
		if enabled:
			fixedEnabled = True
		else:
			fixedEnabled = False
			
		#Create Internal representation
		newCondition = [accessType,fixedBankName,targetType,fixedTarget,condition,fixedValue,tainted,fixedEnabled,False,None,description]
		
		#Check existing conditions, and if this one matches, just return
		#the previous idx
		for idx in xrange(len(self.conditions)):
			if self.conditions[idx] != None and \
				 self.conditions[idx][:7] == newCondition[:7]:
				return idx

		#Add new condition to the list
		self.conditions.append(newCondition)
		idx = len(self.conditions)-1
		return idx
	
	#Convience functions for adding break conditions (maybe these will be helpful
	#for scripting
	def addBreakPoint(self,address,description=None):
		return self.addCondition(BREAKACCESS_BP,BREAKTARGET_NULL,None, BREAKCOND_EQ,address,BREAKTAINTED_ANY,description)	
	def addRegisterValue(self,register,value,description=None):
		return self.addCondition(BREAKACCESS_REG,BREAKTARGET_SINGLE,register,BREAKCOND_EQ,value,BREAKTAINTED_ANY,description)
	def addMemoryValue(self,address_or_symbolName,value,description=None):
		return self.addCondition(BREAKACCESS_RW,BREAKTARGET_SINGLE,address_or_symbolName,BREAKCOND_EQ,value,BREAKTAINTED_ANY,description)
	def addMemoryAccess(self,address_or_symbolName,description=None):
		return self.addCondition(BREAKACCESS_RW,BREAKTARGET_SINGLE,address_or_symbolName,BREAKCOND_EQ,BREAKVALUE_ANY,BREAKTAINTED_ANY,description)
	def addMemoryRead(self,address_or_symbolName,description=None):
		return self.addCondition(BREAKACCESS_R,BREAKTARGET_SINGLE,address_or_symbolName,BREAKCOND_EQ,BREAKVALUE_ANY,BREAKTAINTED_ANY,description)
	def addMemoryWrite(self,address_or_symbolName,description=None):
		return self.addCondition(BREAKACCESS_W,BREAKTARGET_SINGLE,address_or_symbolName,BREAKCOND_EQ,BREAKVALUE_ANY,BREAKTAINTED_ANY,description)
	
	def removeCondition(self,id):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		self.conditions[id] = None
		
	def enableCondition(self,id,enabled=True):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		self.conditions[id][ENABLED] = enabled
			
	def disableCondition(self,id):
		self.enableCondition(id,False)
		
	def isConditionEnabled(self,id):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		return self.conditions[id][ENABLED]
		
	def isConditionTriggered(self,id):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		return self.conditions[id][TRIGGERED]
		
	def clear(self):
		self.conditions = []
		
	def getConditionIds(self):
		return [idx for idx in xrange(len(self.conditions)) if self.conditions[idx] != None]
		
	#This only gets updated when checkConditions is called.
	#It is primarily here to support script that need to quickly
	#check was condition caused an execution break.
	def getTriggeredConditions(self):
		return self.triggeredConditions
		
	def getTriggeredConditionsCount(self):
		return len(self.triggeredConditions)
		
	def checkConditions(self):
		matchedConditions = []
		memRecord = self.mem.getStepRecord()
		for idx in xrange(len(self.conditions)):
			if self.conditions[idx] == None:
				continue
			watchAccess, watchBank, targetType, target, condition, watchValue, watchTainted, enabled = self.conditions[idx][:8]
			self.conditions[idx][TRIGGERED] = False
			if not enabled:
				continue
			if watchAccess == BREAKACCESS_BP:
				pc = self.regs.getProgramCounter()
				value, tainted = self.mem.getMemory(pc)
				if self._compareValues(pc,condition,watchValue) and \
					 self._compareTainted(tainted,watchTainted):
					matchedConditions.append(idx)
					self.conditions[idx][TRIGGERED] = True
			elif watchAccess == BREAKACCESS_REG:
				if targetType == BREAKTARGET_SINGLE:
					target = [target]
				for t in target:
					value, tainted = self.regs.getRegister(t)
					if self._compareValues(value,condition,watchValue) and \
						 self._compareTainted(tainted,watchTainted):
						matchedConditions.append(idx)
						self.conditions[idx][TRIGGERED] = True
			else: #watchAccess in BREAKACCES_MEMTYPES
				for accessRecord in memRecord:
					recordBank, recordAccess, recordAddress, recordValue, recordTainted = accessRecord[:5]
					if self._compareBank(recordBank,watchBank) and \
						 self._compareTarget(recordAddress,targetType,target) and \
						 self._compareAccess(recordAccess,watchAccess) and \
						 self._compareValues(recordValue,condition,watchValue) and \
						 self._compareTainted(recordTainted,watchTainted):
						matchedConditions.append(idx)
						self.conditions[idx][TRIGGERED] = True
		self.triggeredConditions = matchedConditions
		return matchedConditions
				
				
	def _targetToAddress(self,target,range=False):
		if target == RANGE_MIN and range:
			return RANGE_MIN
		elif target == RANGE_MAX and range:
			return RANGE_MAX
		elif type(target) == str:
			if self.program != None:
				symbols = self.program.getSymbolTable().getSymbols(target)
				if symbols.hasNext():
					symbol = symbols.next()
					address = symbol.getAddress().getOffset()
				else:
					try:
						address = int(target,16)
					except ValueError:
						raise ValueError,"target is not a symbol name or hexidecimal address"
			else:
				raise ValueError,"target may be symbol but no ghidra program available for lookup"
		elif type(target) == int:
			address = target
		else:
			raise ValueError,"target is not a symbol name or hexidecimal address"
		return address
	
	def _targetToRegister(self,target):
		for categoryName,regDef in self.regs.getRegistersDefinition():
			for regName, regDisplayName, bitWidth in regDef:
				if target in [regName,regDisplayName]:
					found = True 
					return regName
		raise ValueError,"target %s is not a valid register name" % str(target)
	
	def _compareBank(self,recordBank,watchBank):
		if watchBank == None:
			return True
		elif watchBank == recordBank:
			return True
		else:
			return False
	
	def _compareTarget(self,recordAddress,targetType,target):
		if targetType == BREAKTARGET_SINGLE:
			if recordAddress == target:
				return True
		elif targetType == BREAKTARGET_RANGE:
			if target[0] == RANGE_MIN:
				if target[1] == RANGE_MAX:
					return True
				elif recordAddress <= target[1]:
					return True
			elif target[1] == RANGE_MAX:
				if recordAddress >= target[1]:
					return True
			elif recordAddress >= target[0] and recordAddress <= target[1]:
					return True
		elif targetType == BREAKTARGET_SET:
			for t in target:
				if recordAddress == t:
					return True
		return False
	
	def _compareValues(self,recordValue,condition,watchValue):
		if watchValue == BREAKVALUE_ANY:
			return True
		if condition == BREAKCOND_LT:
			return recordValue < watchValue
		elif condition == BREAKCOND_LTEQ:
			return recordValue <= watchValue
		elif condition == BREAKCOND_EQ:
			return recordValue == watchValue
		elif condition == BREAKCOND_GTEQ:
			return recordValue >= watchValue
		elif condition == BREAKCOND_GT:
			return recordValue > watchValue
		return False
			
	def _compareAccess(self,recordAccess,watchAccess):
		if watchAccess == BREAKACCESS_RW and recordAccess in [AREAD,AWRITE]:
			return True
		elif watchAccess == BREAKACCESS_R and recordAccess == AREAD:
			return True
		elif watchAccess == BREAKACCESS_W and recordAccess == AWRITE:
			return True
		else:
			return False
			
	def _compareTainted(self,recordTainted,watchTainted):
		if watchTainted == BREAKTAINTED_ANY:
			return True
		elif watchTainted == BREAKTAINTED_TAINTED and recordTainted:
			return True
		elif watchTainted == BREAKTAINTED_UNTAINTED and not recordTainted:
			return True
		else:
			return False
	
	#Parses a text script and adds the condition
	#script     := access [condition] watchValue 
	#access     := memAccess | regAccess | bpAccess
	#memAccess  := accessType [bankName] target
	#regAccess  := "REG" target
	#bpAccess   := "BP"
	#accessType := "R" | "W" | "RW"
	#target     := range | set
	#range      := start - end
	#start      := "MIN" | symbolName | address
	#end        := "MAX" | symbolName | address
	#set        := item[, item[, item[...]]]
	#item       := symbolName | address
	#condition  := "<=" | "<" | "==" | ">=" | ">"
	#watchValue := value [tainted] 
	#address    := "[0x]{0,1}[0-F]+"
	#value      := "0x[0-F]+" | "[0-9]+" | "*"
	#tainted    := "T" | "U" 
	def addScriptCondition(self,script,description=None):
		script = str(script)
		originalScript = script
		script = script.replace("-"," - ")
		script = script.replace(","," , ")
		script = script.replace("<"," < ").replace(" < =","<=")
		script = script.replace(">"," > ").replace(" > =",">=")
		script = script.replace("<="," <= ")
		script = script.replace(">="," >= ")
		script = script.replace("=="," == ")
		script = script.strip()
		
		elements = [e for e in script.split(" ") if len(e)]
		if elements[0].upper() not in BREAKACCESS_STRINGS:
			raise ValueError,"Invalid access type"
		accessType = BREAKACCESS_STRINGS.index(elements[0].upper())
		elements = elements[1:]
		
		bankName = None
		if accessType == BREAKACCESS_BP:
			targetType = BREAKTARGET_NULL
			target = None
		elif accessType == BREAKACCESS_REG:
			if len(elements) < 1:
				raise ValueError,"Unable to parse register name"
			targetType = BREAKTARGET_SINGLE
			target = elements[0]
			elements = elements[1:]
		else:
			if len(elements) >= 1:
				if elements[0] in self.mem.getBanks():
					bankName = elements[0]
					elements = elements[1:]

			if len(elements) < 2:
				targetType = BREAKTARGET_SINGLE
				target = elements[0]
				elements = []
			elif elements[1] == "-":
				if len(elements) < 3:
					raise ValueError,"Unable to parse target range"
				targetType = BREAKTARGET_RANGE
				target = [elements[0],elements[2]]
				elements = elements[3:]
			elif elements[1] == ",":
				targetType = BREAKTARGET_SET
				target = []
				while len(elements) > 1 and elements[1] == ",":
					target.append(elements[0])
					elements = elements[2:]
				target.append(elements[0])
				elements = elements[1:]
			else:
				targetType = BREAKTARGET_SINGLE
				target = elements[0]
				elements = elements[1:]
		
		if len(elements) < 1:
			condition = BREAKCOND_EQ
		elif elements[0] in BREAKCOND_STRINGS:
			condition = BREAKCOND_STRINGS.index(elements[0])
			elements = elements[1:]
		else:
			condition = BREAKCOND_EQ
		
		if len(elements) < 1:
			value = BREAKVALUE_ANY
		else:
			value = elements[0]
			elements = elements[1:]
		
		if len(elements) < 1:
			tainted = BREAKTAINTED_ANY
		elif elements[0] in BREAKTAINTED_STRINGS:
			tainted = BREAKTAINTED_STRINGS.index(elements[0])
		else:
			raise ValueError,"Unable to parsed tainted"
		
		id = self.addCondition(accessType,bankName,targetType,target,condition,value,tainted,description)
		self.conditions[id][SCRIPT] = originalScript
		return id
		
	def getConditionScript(self,id):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		if self.conditions[id][SCRIPT] != None:
			return self.conditions[id][SCRIPT]
		
		#"Decompile" a script form of this condition
		elements = []
		watchAccess, bankName, targetType, target, condition, watchValue, watchTainted, enabled, triggered, script = self.conditions[id]
		elements.append(BREAKACCESS_STRINGS.index(watchAccess))
		if bankName != None:
			elements.append(bankName)
		if targetType == BREAKTARGET_SINGLE:
			elements.append(target)
		elif targetType == BREAKTARGET_RANGE:
			elements.append(target[0])
			elements.append("-")
			elements.append(target[1])
		else:
			for i in xrange(len(target)-1):
				elements.append(target[i])
				elements.append(",")
			elements.append(target[-1])
		elements.append(BREAKCOND_STRINGS[condition])
		if watchValue == BREAKVALUE_ANY:
			elements.append("*")
		else:
			elements.append(watchValue)
		elements.append(BREAKTAINTED_STRINGS[watchTainted])
		
		for i in xrange(len(elements)):
			if type(elements[i]) != str:
				elements[i] = "%X"%elements[i]
				
		script = " ".join(elements)
		self.conditions[id][SCRIPT] = script
		return script
		
	def getConditionDescription(self,id):
		if id < 0 or id >= len(self.conditions) or self.conditions[id] == None:
			raise ValueError,"id is not valid"
		return self.conditions[id][DESCRIPTION]