import sys
import threading
import traceback
import struct

from ghidra.app.plugin.assembler import Assemblers
from ghidra.app.plugin.assembler import AssemblySyntaxException
from ghidra.app.plugin.assembler import AssemblySemanticException
from ghidra.program.model.mem import MemoryAccessException
from ghidra.app.plugin.assembler.sleigh.sem import AssemblyPatternBlock
from ghidra.program.model.lang import RegisterValue
from java.math import BigInteger

import jarray

SCRIPTTYPE_PYTHON = 0
SCRIPTTYPE_DB	 = 1

class ScriptEngine:
	def __init__(self, cpu, regs, mem, breakConditions, control, logger, ghidraProgram, updateFunc, memPanel):
		self.pyEngine = PythonScriptEngine(cpu, regs, mem, breakConditions, control, logger, ghidraProgram, updateFunc, memPanel)
		self.dbEngine = DBScriptEngine(cpu, regs, mem, breakConditions, control, logger, ghidraProgram, updateFunc, memPanel)
		self.currentEngine = self.pyEngine
		
	def setEngine(self,scriptType):
		if scriptType == SCRIPTTYPE_PYTHON:
			self.currentEngine = self.pyEngine
		elif scriptType == SCRIPTTYPE_DB:
			self.currentEngine = self.dbEngine
		else:
			raise ValueError, "scriptType is invalid"
			
	def execute(self,script):
		s = self.currentEngine.execute(script)
		return s
		
	def executeFile(self,path):
		return self.currentEngine.executeFile(path)
		
	def getOutput(self):
		return self.currentEngine.getOutput()

class ScriptAPI:
	def __init__(self, cpu, regs, mem, breakConditions, control, logger, ghidraProgram, updateFunc, memPanel):
		self.cpu = cpu
		self.registers = regs
		self.regs = regs
		self.memory  = mem
		self.mem = mem
		self.breakConditions = breakConditions
		self.emulationControl = control
		self.control = control
		self.logger = logger
		self.emulationLogger = logger
		self.ghidraProgram = ghidraProgram
		self.__updateFunc = updateFunc
		self.__memPanel = memPanel
		self.__defaultBankName = None
		self.__breakCallbacks = {}
		self.__masterBreakCallback = None
		self.control.setBreakCallback(self.__handleBreak)
	
	def __handleBreak(self):
		contExec =  None
		for id in self.breakConditions.getTriggeredConditions():
			callback = self.__breakCallbacks.get(id,None)
			if callback != None:
				result = callback()
				if contExec == None or not result:
					contExec = result
			else:
				contExec = False
		if self.__masterBreakCallback != None:
			result = self.__masterBreakCallback()
			if contExec == None or not result:
				contExec = result
		if contExec == None:
			contExec = False
		return contExec
	
	def getReg(self, regName, withTaint=False):
		value, taint = self.regs.getRegister(regName)
		if withTaint:
			return value,taint
		return value

	def setReg(self, regName, value, taint=0):
		self.regs.setRegister(regName, value, taint)
	
	def setDefaultBank(self, bankName):
		self.__defaultBankName = bankName
	
	def getByte(self, address, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		value, taint = self.mem.getByte(address,bankName)
		if withTaint:
			return value, taint
		return value
		
	def getWord(self, address, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		value, taint = self.mem.getWord(address,bankName)
		if withTaint:
			return value, taint
		return value
		
	def getDword(self, address, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		value, taint = self.mem.getDword(address,bankName)
		if withTaint:
			return value, taint
		return value
		
	def getQword(self, address, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		value, taint = self.mem.getQword(address,bankName)
		if withTaint:
			return value, taint
		return value
	
	def getByteReadValues(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		return self.mem.getByteReadValues(address,bankName)

	def getWordReadValues(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		return self.mem.getWordReadValues(address,bankName)
		
	def getDwordReadValues(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		return self.mem.getDwordReadValues(address,bankName)

	def getQwordReadValues(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		return self.mem.getQwordReadValues(address,bankName)

	def getStruct(self, address, fmt, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		readLen = struct.calcsize(fmt)
		structBytesWithTaint = [self.mem.getByte(address+i,bankName) for i in xrange(readLen)]
		structString = "".join([chr(x[0]) for x in structBytesWithTaint])
		values = struct.unpack(fmt,structString)
		if withTaint:
			taint = 0
			for bValue, bTaint in structBytesWithTaint:
				taint = taint | bTaint
			return values, taint
		return values
		
	def getString(self, address, withTaint=False, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		strChars = []
		taint = 0
		for i in xrange(256):
			byteValue, byteTaint = self.mem.getByte(address+i,bankName)
			taint = taint | byteTaint
			if byteValue == 0:
				break
			strChars.append(chr(byteValue))
		if withTaint:
			return "".join(strChars), taint
		return "".join(strChars)
		
	def setByte(self, address, value, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setByte(address, value, taint, bankName)

	def setWord(self, address, value, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setWord(address, value, taint, bankName)
		
	def setDword(self, address, value, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setDword(address, value, taint, bankName)
		
	def setQword(self, address, value, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setQword(address, value, taint, bankName)

	def setByteReadValues(self, address, values, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setByteReadValues(address,values,bankName)

	def setWordReadValues(self, address, values, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setWordReadValues(address,values,bankName)
		
	def setDwordReadValues(self, address, values, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setDwordReadValues(address,values,bankName)

	def setQwordReadValues(self, address, values, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setQwordReadValues(address,values,bankName)
		
	def setStruct(self, address, fmt, *args, **kwargs):
		taint = kwargs.get("taint",0)
		bankName  = kwargs.get("bank",None)
		if bankName == None:
			bankName = self.__defaultBankName
		structBytes = [ord(x) for x in struct.pack(fmt,*args)]
		for i in xrange(len(structBytes)):
			self.mem.setByte(address+i, structBytes[i], taint, bankName)
	
	def setString(self, address, s, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		for i in xrange(len(s)):
			self.mem.setByte(address+i, ord(s[i]), taint, bankName)
		self.mem.setByte(address+len(s), 0, taint, bankName)
	
	def setAssembly(self, address, listing, taint=0, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		assembledBytes = self.assemble(address,listing,useContextReg=True)
		for i in xrange(len(assembledBytes)):
			self.mem.setByte(address+i, assembledBytes[i], taint, bankName)
	
	def setMutable(self, address, mutable=True, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.setMutable(address, mutable, bankName)
		
	def isMutable(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.mem.isMutable(address, bankName)
		
	def resetMemory(self):
		self.mem.reset()
		self.updateUI()
		
	def resetCpu(self):
		self.regs.reset()
		self.updateUI()
		
	def step(self,handleBreaks=False):
		self.control.step()
		if handleBreaks and self.breakConditions.getTriggeredConditionsCount():
			self.__handleBreak()
		self.updateUI()
		
	def unstep(self,handleBreaks=False):
		self.control.unstep()
		if handleBreaks and self.breakConditions.getTriggeredConditionsCount():
			self.__handleBreak()
		self.updateUI()
		
	def run(self):
		self.control.run()
		
	def setBreakCallback(self, callback):
		self.__masterBreakCallback = callback
		
	def watchByte(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.__memPanel.memModel.addRows(bankName, [address], 1)
		self.updateUI()

	def watchWord(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.__memPanel.memModel.addRows(bankName, [address], 2)
		self.updateUI()
		
	def watchDword(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.__memPanel.memModel.addRows(bankName, [address], 4)
		self.updateUI()
		
	def watchQword(self, address, bankName=None):
		if bankName == None:
			bankName = self.__defaultBankName
		self.__memPanel.memModel.addRows(bankName, [address], 8)
		self.updateUI()
				
	def clearWatch(self):
		self.__memPanel.memModel.removeAllRows()
		self.updateUI()
				
	def addBreak(self, script, description=None, callback=None):
		id = self.breakConditions.addScriptCondition(script,description)
		if callback != None:
			self.__breakCallbacks[id] = callback
		self.updateUI()
		return id
		
	def enableBreak(self, id):
		self.breakConditions.enableCondition(id)
		self.updateUI()
		
	def disableBreak(self, id):
		self.breakConditions.disableCondition(id)
		self.updateUI()
		
	def removeBreak(self, id):
		self.breakConditions.removeCondition(id)
		try:
			del self.__breakCallbacks[id]
		except KeyError:
			pass
		self.updateUI()
		
	def clearBreak(self):
		self.breakConditions.clear()
		self.__breakCallbacks = {}
		self.updateUI()
		
	def checkBreak(self, id):
		return self.breakConditions.isConditionTriggered(id)
		
	def getBreak(self):
		return self.breakConditions.getTriggeredConditions()
		
	def getSymbolAddress(self, name):
		symbols = self.ghidraProgram.getSymbolTable().getSymbols(name)
		if symbols.hasNext():
			symbol = symbols.next()
		else:
			return None
		address = symbol.getAddress().getOffset()
		return address
		
	def startTrace(self, path):
		fp = open(path,"wb")
		self.logger.startLogging(fp)
		
	def stopTrace(self):
		self.logger.stopLogging()
		
	def updateUI(self):
		self.__updateFunc()
		
	def setSpeed(self,skip):
		self.control.setStepCallbackSkip(skip)
	
	def saveState(self,path):
		fp = open(path,"wb")
		self.control.saveState(fp)
		fp.close()
		
	def loadState(self,path):
		fp = open(path,"rb")
		self.control.loadState(fp)
		fp.close()
		self.updateUI()
	
	def patchBytes(self,address,patchBytes):
		assembler = Assemblers.getAssembler(self.ghidraProgram)
		if type(patchBytes) == str:
			jBytes = jarray.array(struct.unpack("b"*len(patchBytes),patchBytes),"b")
		else:
			jBytes = jarray.array(struct.unpack("b"*len(patchBytes),struct.pack("B"*len(patchBytes),*patchBytes)),"b")
		jAddr  = self.ghidraProgram.getAddressFactory().getAddress("0x%X" % int(address))
		if jAddr == None:
			raise ValueError,"Address 0x%X is invalid" % int(address)
		transId = self.ghidraProgram.startTransaction("divetBytePatch")
		try:
			assembler.patchProgram(jBytes,jAddr)
		except MemoryAccessException, err:
			self.ghidraProgram.endTransaction(transId,False)
			raise err
		except Exception, err:
			self.ghidraProgram.endTransaction(transId,False)
			raise err
		self.ghidraProgram.endTransaction(transId,True)
	
	def patchProgram(self,address,listing):
		self.patchBytes(address, self.assemble(address,listing))
	
	def assemble(self,address,listing,useContextReg=False):
		assembler = Assemblers.getAssembler(self.ghidraProgram)
		if useContextReg:
			ctxReg = self.ghidraProgram.getLanguage().getContextBaseRegister()
			if ctxReg != None:
				#The use of a RegisterValue is a work-around because AssemblyPatternBlock.fromLong() is broken
				ctxRegValue = RegisterValue(ctxReg,BigInteger(str(self.getReg(ctxReg.getName()))))
				jCtx = AssemblyPatternBlock.fromRegisterValue(ctxRegValue)
			else:
				useContextReg = False
		if type(listing) == str:
			listing = listing.split("\n")
		instrAddress = address
		assembledBytes = []
		lineIdx = 0
		for lineIdx in xrange(len(listing)):
			instr = listing[lineIdx].strip()
			jAddr  = self.ghidraProgram.getAddressFactory().getAddress("0x%X"%int(instrAddress))
			if jAddr == None:
				raise ValueError,"Line %d, %s -  Address 0x%X is invalid" % (lineIdx+1,repr(instr),int(instrAddress))
			if not useContextReg:
				jCtx = assembler.getContextAt(jAddr).fillMask()
			try:
				jBytes = assembler.assembleLine(jAddr,instr,jCtx)
			except AssemblySyntaxException, e:
				raise ValueError,"Line %d, %s - Syntax error" % (lineIdx+1,repr(instr))
			except AssemblySemanticException, e:
				raise ValueError,"Line %d, %s - Semantic error" % (lineIdx+1,repr(instr))
			instrBytes = struct.unpack("B"*len(jBytes),struct.pack("b"*len(jBytes),*jBytes))
			instrAddress = instrAddress + len(instrBytes)
			assembledBytes.extend(instrBytes)
		return assembledBytes
		
	def setupFunctionCall(self, funcName, args):
		func = self.ghidraProgram.getListing().getGlobalFunctions(funcName)
		if len(func) == 0:
			raise ValueError("Invalid function name")
		func = func[0]
		funcAddr = func.getEntryPoint().getUnsignedOffset()
		print("Function address is 0x%X" % funcAddr)
		self.setReg("PC", funcAddr, False)
		params = func.getParameters()
		for i in range(len(params)):
			param = params[i]
			arg = args[i]
			if param.isRegisterVariable():
				reg = param.getRegister()
				self.setReg(reg.getName(), arg, False)
			elif param.isStackVariable():
				offset = param.getStackOffset()
				raise NotImplementedError("Stack variables currently unsupported")
			elif param.isMemoryVariable():
				addr = param.getMinimumAddress()
				size = param.getDataType().getLength()
				if size == 1:
					self.setByte(addr, arg)
				elif size == 2:
					self.setWord(addr, arg)
				elif size == 4:
					self.setDword(addr, arg)
				elif size == 8:
					self.setQword(addr, arg)
				else:
					raise ValueError("Unknown parameter type/size")
			else:
				raise ValueError("Unknown parameter type")
		self.__updateFunc()
		


class DummyStdOut:
	def __init__(self):
		self.buffer = ""
		self.lock = threading.Lock()
		
	def write(self, str):
		self.lock.acquire()
		self.buffer = "".join([self.buffer, str])
		self.lock.release()
		
	def read(self, size=None):
		self.lock.acquire()
		if size == None or size < 0:
			size = len(self.buffer)
		elif size > len(self.buffer):
			size = len(self.buffer)
		output = self.buffer[:size]
		self.buffer = self.buffer[size:]
		self.lock.release()
		return output


class PythonScriptEngine:
	def __init__(self, cpu, regs, mem, watch, control, logger, ghidraProgram, updateFunc, memPanel):
		self.updateFunc = updateFunc
		self.stdout = DummyStdOut()
		self.scriptGlobals = {}
		api = ScriptAPI(cpu, regs, mem, watch, control, logger, ghidraProgram, updateFunc, memPanel)
		self.scriptGlobals["api"]		 = api
		self.scriptGlobals["getReg"]	 = api.getReg
		self.scriptGlobals["setReg"]	 = api.setReg
		self.scriptGlobals["setBank"]    = api.setDefaultBank
		self.scriptGlobals["getByte"]	 = api.getByte
		self.scriptGlobals["getWord"]	 = api.getWord
		self.scriptGlobals["getDword"]   = api.getDword
		self.scriptGlobals["getQword"]   = api.getQword
		self.scriptGlobals["getByteRV"]  = api.getByteReadValues
		self.scriptGlobals["getWordRV"]  = api.getWordReadValues
		self.scriptGlobals["getDwordRV"] = api.getDwordReadValues
		self.scriptGlobals["getQwordRV"] = api.getQwordReadValues
		self.scriptGlobals["getStruct"]  = api.getStruct
		self.scriptGlobals["getString"]  = api.getString
		self.scriptGlobals["setByte"]	 = api.setByte
		self.scriptGlobals["setWord"]	 = api.setWord
		self.scriptGlobals["setDword"]   = api.setDword
		self.scriptGlobals["setQword"]   = api.setQword
		self.scriptGlobals["setByteRV"]  = api.setByteReadValues
		self.scriptGlobals["setWordRV"]  = api.setWordReadValues
		self.scriptGlobals["setDwordRV"] = api.setDwordReadValues
		self.scriptGlobals["setQwordRV"] = api.setQwordReadValues
		self.scriptGlobals["setStruct"]  = api.setStruct
		self.scriptGlobals["setString"]  = api.setString
		self.scriptGlobals["setAssembly"]= api.setAssembly
		self.scriptGlobals["setMutable"] = api.setMutable
		self.scriptGlobals["isMutable"]  = api.isMutable
		self.scriptGlobals["resetMem"]   = api.resetMemory
		self.scriptGlobals["resetCpu"]   = api.resetCpu
		self.scriptGlobals["step"]	     = api.step
		self.scriptGlobals["unstep"]	 = api.unstep
		self.scriptGlobals["run"]		 = api.run
		self.scriptGlobals["setCB"]	     = api.setBreakCallback
		self.scriptGlobals["watchByte"]  = api.watchByte
		self.scriptGlobals["watchWord"]  = api.watchWord
		self.scriptGlobals["watchDword"] = api.watchDword
		self.scriptGlobals["watchQword"] = api.watchQword
		self.scriptGlobals["clrWatch"]   = api.clearWatch
		self.scriptGlobals["addBrk"]	 = api.addBreak
		self.scriptGlobals["enaBrk"]	 = api.enableBreak
		self.scriptGlobals["disBrk"]	 = api.disableBreak
		self.scriptGlobals["rmBrk"]	     = api.removeBreak
		self.scriptGlobals["clrBrk"]	 = api.clearBreak
		self.scriptGlobals["isBrk"]	     = api.checkBreak
		self.scriptGlobals["getBrk"]	 = api.getBreak
		self.scriptGlobals["getSym"]	 = api.getSymbolAddress
		self.scriptGlobals["startTrace"] = api.startTrace
		self.scriptGlobals["stopTrace"]  = api.stopTrace
		self.scriptGlobals["setSpeed"]   = api.setSpeed
		self.scriptGlobals["setupFunc"]  = api.setupFunctionCall
		self.scriptGlobals["saveState"]  = api.saveState
		self.scriptGlobals["loadState"]  = api.loadState
		self.scriptGlobals["patchBytes"] = api.patchBytes
		self.scriptGlobals["patchProg"]  = api.patchProgram
		self.scriptGlobals["assemble"]   = api.assemble
		
		
	def execute(self, script):
		savedStdOut = sys.stdout
		savedStdErr = sys.stderr
		sys.stdout = self.stdout
		sys.stderr = self.stdout
		#Try to evaluate first and capture the result
		try:
			result = eval(script,self.scriptGlobals)
			if result == None:
				result = ""
			elif type(result) in [int, long]:
				result = "0x%X\n" % result
			else:
				result = "%s\n" % str(result)
		except SyntaxError:
			result = ""
			#It's possible that the script contained either
			#an assignment or a print, so try to exec it
			#and ignore any result
			try:
				exec(script, self.scriptGlobals)
			except:
				traceback.print_exc()
		except:
			result = ""
			traceback.print_exc()
		sys.stdout = savedStdOut
		sys.stderr = savedStdErr
		self.updateFunc()
		return "\n".join([x for x in [self.getOutput(), result] if len(x)])
	
	def executeFile(self, path):
		savedStdOut = sys.stdout
		savedStdErr = sys.stderr
		sys.stdout = self.stdout
		sys.stderr = self.stdout
		try:
			execfile(path, self.scriptGlobals)
		except:
			traceback.print_exc()
		sys.stdout = savedStdOut
		sys.stderr = savedStdErr
		self.updateFunc()
		
	def getOutput(self):
		return self.stdout.read()
		
class DBScriptEngine:
	# Scripting Engine
	# This class is intended to provide the framework for parsing a basic scripting format
	
	# Supported operations:
	# # function(arg1, arg2, arg3)		Call function as named in database
	# # var = expression				Assign value to scripting variable
	# # *var = expression				Assign value to memory location stored in scripting variable
	# # *address = expression			Assign value to memory location
	
	# Supported expressions:
	# # Function calls (see above)
	# # Arithmetic operators (+, -, *, /)
	# # Binary operators (^, &, |, >>, <<)
	# # Comparison operators (>, <, ==)
	
	# Can embed expressions within functions, and can chain expressions
	# Multiple or nested function calls on same line not supported
	# Parenthesis are not implemented
	
	def __init__(self, cpu, regs, mem, watch, control, logger, ghidraProgram, updateFunc, memPanel):
		self.cpu = cpu
		self.regs = regs
		self.emuMem = mem
		self.logger = logger
		self.program = ghidraProgram
		self.updateFunc = updateFunc
		self.variables = {}

	def execute(self, command):
		value = self.parse(command)
		if value is not None:
			return str(value) + "\n"
	
	def executeFile(self, script):
		pass
		
	def getOutput(self):
		return ""
	
	# Search the input string for the matching parenthesis at the given index
	def findMatchingParen(self, inputStr, index):
		match = inputStr[index]
		count = 1
		for i in range(index + 1, len(inputStr)):
			if inputStr[i] == "(":
				count += 1
			elif inputStr[i] == ")":
				count -= 1
				if count == 0:
					return i
		raise ValueError("Invalid Expression:  Unmatched paren")
	
	# Handles parsing numbers (both hex (0x) and decimal) and variables
	# Returns the numeric value of the literal and the remaining input string
	def parseLiteral(self, inputStr):
		isHex = False
		startIndex = 0
		if len(inputStr) > 1 and inputStr[0:2] == "0x":
			startIndex = 2
			isHex = True
		endIndex = startIndex + 1
		if inputStr[startIndex].isdecimal() or isHex:
			# Parsing number
			while endIndex < len(inputStr) and (inputStr[endIndex].isdecimal() or inputStr[endIndex] in "AaBbCcDdEeFf"):
				endIndex += 1
			if isHex:
				num = int(inputStr[startIndex : endIndex], 16)
			else:
				num = int(inputStr[startIndex : endIndex])
		else:
			# Parsing variable
			while endIndex < len(inputStr) and (inputStr[endIndex].isalnum() or inputStr[endIndex] == "_"):
				endIndex += 1
			num = self.variables[inputStr[startIndex : endIndex]]
		return num, inputStr[endIndex:].strip()
	
	# Handles parsing an expression that returns a value
	# Takes input string, returns value
	# TODO:  Add support for order of operations
	def parseExpression(self, inputStr):
		inputStr = inputStr.strip()
		if inputStr == "":
			return None
		lValue = None
		isRef = (inputStr[0] == "*")
		if isRef:
			# Mark that the parsed value needs to be dereferenced
			inputStr = inputStr[1:]
		if inputStr[0] == "(":
			# Parse paren expression
			rParen = self.findMatchingParen(inputStr, 0)
			value = self.parseExpression(inputStr[1:rParen])	# Parse between the parens
			inputStr = inputStr[rParen + 1:].strip()			# Resume after parens
		elif inputStr[0].isalnum() or inputStr[0] == "_":
			value, inputStr = self.parseLiteral(inputStr)
		else:
			raise ValueError("Incorrect expression syntax")
		if isRef:
			# Dereference
			value = self.memoryRead(value)
			
		if len(inputStr) > 0:
			# Check for any unparsed characters (should only be operators)
			if inputStr[0] in "*/^&|+-><":
				operator = inputStr[0]
				inputStr = inputStr[1:].strip()
			elif inputStr[0:2] in [">>", "<<", "=="]:
				operator = inputStr[0:2]
				inputStr = inputStr[2:].strip()
			else:
				raise ValueError("Incorrect operator syntax")
			# Parse the right side of the operator
			rValue = self.parseExpression(inputStr)
			# Compute the operation
			if operator == "+":
				value += rValue
			elif operator == "-":
				value -= rValue
			elif operator == "*":
				value *= rValue
			elif operator == "/":
				value /= rValue
			elif operator == "|":
				value |= rValue
			elif operator == "&":
				value &= rValue
			elif operator == "^":
				value ^= rValue
			elif operator == ">":
				value == value > rValue
			elif operator == "<":
				value = value < rValue
			elif operator == "==":
				value = (value == rValue)
			elif operator == ">>":
				value >>= rValue	
			elif operator == "<<":
				value <<= rValue
			else:
				raise ValueError("Mishandled operator")
		return value
	
	# Entry function for parsing an expression, function call, or assignment operation
	def parse(self, inputStr):
		inputStr = inputStr.strip()
		if inputStr == "":
			return
		
		startIndex = 1
		while startIndex < len(inputStr):
			if inputStr[startIndex] != "=":
				startIndex += 1
			elif inputStr[startIndex : startIndex + 2] == "==":
				startIndex += 2
			else:
				# Should be single = sign
				left = inputStr[:startIndex].strip()
				right = inputStr[startIndex + 1:].strip()
				right = self.parseExpression(right)
				if left[0] == "*":
					left = self.parseExpression(left[1:])
					self.memoryWrite(left, right)
				elif left[0].isalpha():
					self.variables[left] = right
				else:
					raise ValueError("Invalid expression assignment")
				return
		
		if inputStr[0].isalpha() and "(" in inputStr:
			# Function
			endIndex = 1
			while inputStr[endIndex].isalnum() or inputStr[endIndex] == "_":
				endIndex += 1
			name = inputStr[0:endIndex]
			print(name)
			if inputStr[endIndex] == "(":
				# Parse params and handle function call
				endParenIndex = self.findMatchingParen(inputStr, endIndex)
				args = inputStr[endIndex + 1 : endParenIndex].split(",")
				params = [self.parseExpression(arg) for arg in args]
				self.setupFunctionCall(name, params)
				return
		# Expression
		return self.parseExpression(inputStr)
	
	# Sets the register value
	def setRegister(self, reg, value, taint):
		self.regs.setRegister(reg, value, taint)
		self.updateFunc()

	# Sets the program state as if a function is being called
	def setupFunctionCall(self, funcName, args):
		func = self.program.getListing().getGlobalFunctions(funcName)
		if len(func) == 0:
			raise ValueError("Invalid function name")
		func = func[0]
		funcAddr = func.getEntryPoint().getUnsignedOffset()
		print("Function address is 0x%X" % funcAddr)
		self.regs.setRegister("PC", funcAddr, False)
		params = func.getParameters()
		for i in range(len(params)):
			param = params[i]
			arg = args[i]
			if param.isRegisterVariable():
				reg = param.getRegister()
				print("Reg %s is %d" % (reg.getName(), arg))
				self.regs.setRegister(reg.getName(), arg, False)
			elif param.isStackVariable():
				offset = param.getStackOffset()
				raise NotImplementedError("Stack variables currently unsupported")
			elif param.isMemoryVariable():
				addr = param.getMinimumAddress()
				size = param.getDataType().getLength()
				taint = self.emuMem.isTainted(address)
				if size == 1:
					self.emuMem.setByte(addr, arg, taint)
				elif size == 2:
					self.emuMem.setWord(addr, arg, taint)
				elif size == 4:
					self.emuMem.setDword(addr, arg, taint)
				elif size == 8:
					self.emuMem.setQword(addr, arg, taint)
			else:
				raise ValueError("Unknown parameter type")
		self.updateFunc()
	
	# Write a byte value to an address
	# TODO:  Allow multi-byte write operations
	def memoryWrite(self, address, value, size=1):
		taint = self.emuMem.isTainted(address)
		if size == 1:
			self.emuMem.setByte(address, value, taint)
		elif size == 2:
			self.emuMem.setWord(address, value, taint)
		elif size == 4:
			self.emuMem.setDword(address, value, taint)
		elif size == 8:
			self.emuMem.setQword(address, value, taint)
		print("Wrote %d to 0x%X" % (value, address))
	
	# Read a byte from a memory address
	# TODO:  allow multi-byte read operations
	def memoryRead(self, address):
		print("Reading from 0x%X" % address)
		return self.emuMem.read(address)[0]