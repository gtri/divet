import struct

from cpu import *

ALFLAG_AWORD  = 0
ALFLAG_NORMAL = 1

ADDR_TYPE_REG16 = 3


class RegistersX(Registers):
	def __init__(self):
		Registers.__init__(self)
		self.alFlag = ALFLAG_NORMAL
		
	def getRegistersDefinition(self):
		return [
		["Special",[["R0","PC/R0",20],["R1","SP/R1",20]]],
		["Flags/R3",[["V","oVerflow",1],["SCG1","SysClkGen1",1],["SCG0","SysClkGen2",1],["OSCOFF","OscOff",1],["CPUOFF","CPU Off",1],["GIE","General Int Enable",1],["N","Negative",1],["Z","Zero",1],["C","Carry",1]]],
		["General",[["R4","R4",20],["R5","R5",20],["R6","R6",20],["R7","R7",20],["R8","R8",20],["R9","R9",20],["R10","R10",20],["R11","R11",20],["R12","R12",20],["R13","R13",20],["R14","R14",20],["R15","R15",20]]]
		]
		
	def getState(self):
		values = [getattr(self,regname,0) for regname in self.regs]+[getattr(self,"%s_taint" % regname,0) for regname in self.regs]
		return struct.pack(">IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",*values)
		
	def setState(self,state):
		self.R0, self.R1, self.R2, self.R3, self.R4, self.R5, self.R6, self.R7, self.R8, self.R9, self.R10, self.R11, self.R12, self.R13, self.R14, self.R15, self.R0_taint, self.R1_taint, self.R2_taint, self.R3_taint, self.R4_taint, self.R5_taint, self.R6_taint, self.R7_taint, self.R8_taint, self.R9_taint, self.R10_taint, self.R11_taint, self.R12_taint, self.R13_taint, self.R14_taint, self.R15_taint = struct.unpack(">IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII",state)
		if (self.R0 & 1) != 0:
			raise ValueError,"R0/PC must be even" 

class FlaggedRegistersWrapperX(FlaggedRegistersWrapper):
	def __init__(self,registers):
		FlaggedRegistersWrapper.__init__(self,registers)
		self.__dict__["alFlag"] = ALFLAG_NORMAL
		
	def setAlFlag(self,alFlag=ALFLAG_NORMAL):
		self.alFlag = alFlag
		
	def getRegister(self,regname,bwFlag=None,alFlag=None):
		if alFlag == None:
			alFlag = self.alFlag
		if bwFlag == None:
			bwFlag = self.bwFlag
		
		value, taint = self.r.getRegister(regname)
		
		if alFlag == ALFLAG_NORMAL:
			if bwFlag == BWFLAG_BYTE:
				value = value & 0xFF
			elif bwFlag == BWFLAG_WORD:
				value = value & 0xFFFF
			else:
				raise ValueError,"B/W Flag is invalid: %d" % bwFlag
		elif alFlag == ALFLAG_AWORD:
			value = value & 0xFFFFF
		else:
			raise ValueError,"A/L Flag is invalid: %d" % alFlag
			
		return value, taint
			
	def setRegister(self,regname,value,taint=0,bwFlag=None,alFlag=None):
		if alFlag == None:
			alFlag = self.alFlag
		if bwFlag == None:
			bwFlag = self.bwFlag
		
		if alFlag == ALFLAG_NORMAL:
			if bwFlag == BWFLAG_BYTE:
				value = value & 0xFF
			elif bwFlag == BWFLAG_WORD:
				value = value & 0xFFFF
			else:
				raise ValueError,"B/W Flag is invalid: %d" % bwFlag
		elif alFlag == ALFLAG_AWORD:
			value = value & 0xFFFFF
		else:
			raise ValueError,"A/L Flag is invalid: %d" % alFlag
			
		self.r.setRegister(regname,value,taint)
		
	def reset(self):
		FlaggedRegistersWrapper.reset(self)
		self.__dict__["alFlag"] = ALFLAG_NORMAL
		
class CPUX(CPU):
	MOVA  =  0
	CMPA  =  1
	ADDA  =  2
	SUBA  =  3
	RRCM  =  4
	RRAM  =  5
	RLAM  =  6
	RRUM  =  7
	CALLA =  8
	PUSHM =  9
	POPM  = 10	
	
	def __init__(self,registers,memory):
		self.r = FlaggedRegistersWrapperX(registers)
		self.mem = LittleEndianMemoryWrapper(memory)
		self._postStep() #Reset any instruction decode variables

		#All of these instructions are alFlag=ALFLAG_AWORD (20 bit)
		self.CPUX_FORMATI = {
			0b0000: [self.MOVA,self._srcIndirect,self._destRegister],
			0b0001: [self.MOVA,self._srcIndirectAutoIncrement,self._destRegister],
			0b0010: [self.MOVA,self._srcAbsolute,self._destRegister],
			#0b0011: [self.MOVA,self._srcRegister16, self._destRegister],
			0b0011: [self.MOVA,self._srcIndexed, self._destRegister],
			0b0110: [self.MOVA,self._srcRegister,self._destAbsolute],
			0b0111: [self.MOVA,self._srcRegister,self._destRegister16],
			0b1000: [self.MOVA,self._srcImmediate,self._destRegister],
			0b1001: [self.CMPA,self._srcImmediate,self._destRegister],
			0b1010: [self.ADDA,self._srcImmediate,self._destRegister],
			0b1011: [self.SUBA,self._srcImmediate,self._destRegister],
			0b1100: [self.MOVA,self._srcRegister,self._destRegister],
			0b1101: [self.CMPA,self._srcRegister,self._destRegister],
			0b1110: [self.ADDA,self._srcRegister,self._destRegister],
			0b1111: [self.SUBA,self._srcRegister,self._destRegister],
		}
		
		#All of these instruction are bwFlag=BWFLAG_WORD, but some will
		#have this over-ridden by alFlag=FLAG_AWORD.
		#All have a destination type of Register
		#All of these also lack a "source", but a repeat count.
		self.CPUX_ROTM = {
			0b000100: [self.RRCM,ALFLAG_AWORD],
			0b010100: [self.RRAM,ALFLAG_AWORD],
			0b100100: [self.RLAM,ALFLAG_AWORD],
			0b110100: [self.RRUM,ALFLAG_AWORD],
			0b000101: [self.RRCM,ALFLAG_NORMAL],
			0b010101: [self.RRAM,ALFLAG_NORMAL],
			0b100101: [self.RLAM,ALFLAG_NORMAL],
			0b110101: [self.RRUM,ALFLAG_NORMAL],
		}

		#Data structure format: [shift, value after shift, opcode enum, afFlag, srcFunc] 
		self.CPUX_FORMATII = [
			[4, 0x134,self.CALLA,ALFLAG_AWORD,self._srcRegister,None],
			[4, 0x135,self.CALLA,ALFLAG_AWORD,self._srcIndexed,None],
			[4, 0x136,self.CALLA,ALFLAG_AWORD,self._srcIndexed,None],
			[4, 0x137,self.CALLA,ALFLAG_AWORD,self._srcIndirectAutoIncrement,None],
			[4, 0x138,self.CALLA,ALFLAG_AWORD,self._srcAbsolute,None],
			[4, 0x139,self.CALLA,ALFLAG_AWORD,self._srcSymbolic,None],
			[4, 0x13B,self.CALLA,ALFLAG_AWORD,self._srcImmediate,None],
			[8,  0x14,self.PUSHM,ALFLAG_AWORD,None,None],
			[8,  0x15,self.PUSHM,ALFLAG_NORMAL,None,None],
			[8,  0x16,self.POPM,ALFLAG_AWORD,None,None],
			[8,  0x17,self.POPM,ALFLAG_NORMAL,None,None],
		]
	
	def interruptPush(self):
			pc, pcTaint = self.r.getRegister("R0")
			sr, srTaint = self.r.getRegister("R3")
			self.r.r.R1 = self.r.r.R1 - 2
			self.mem.writeWord(self.r.r.R1, ((sr&0x0FFF)<<4) | ((pc>>16)&0xF), srTaint | pcTaint)
			self.r.r.R1 = self.r.r.R1 - 2
			self.mem.writeWord(self.r.r.R1, pc&0xFFFF, pcTaint) 
	
	def interruptPop(self):
			pc, pcTaint = self.mem.readWord(self.r.r.R1)
			self.r.r.R1 = self.r.r.R1 + 2
			sr, srTaint = self.mem.readWord(self.r.r.R1)
			self.r.r.R1 = self.r.r.R1 + 2
			pc = ((sr&0xF)<<16) | (pc&0xFFFF)
			pcTaint = srTaint | pcTaint
			sr = sr>>4
			self.r.setRegister("R0", pc, pcTaint)
			self.r.setRegister("R3", sr, srTaint)
	
	def _preStep(self):
		#Check for a preamble extension word
		instrWord, instrTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		formatId = (instrWord >> 11) & 0xFF
		if formatId == 3:
			#This is an extension word.  Decode all possible 
			#interpretations and use them later when we decode
			#the actual instruction with addressing mode.
			self.extWord = instrWord
			self.zcFlag = (instrWord&0x0100) >> 8
			repFlag = (instrWord&0x0080) >> 7
			self.alFlag = (instrWord&0x0040) >> 6
			self.r.setAlFlag(self.alFlag)
			repAddr = (instrWord&0x000F)
			if repFlag:
				repReg, regTaint = self.getRegister(repAddr)
				self.repCount = (repReg&0xF)+1
			else:
				self.repCount = repAddr+1
			self.extInstrSrc  = (instrWord&0x0780)>>7
			self.extInstrDest = (instrWord&0x000F)
			#Now perform the normal fetch of the instruction
			#This words was extending
			CPU._preStep(self)
		else:
			self.instrWord = instrWord
			self.repCount = 1
	
	def _step(self):
		#CPUX instructions that require an extension word are handled
		#by overloaded function throughout the decoded/processing chain.
		# 1)Check to see if this is a CPUX instruction that does not 
		#   require an extension word, and if so execute it.
		# 2)Otherwise perform the normal decode/processing chain (with
		#   several overloaded methods along the way).
		if self._decodeExtended():
			for i in xrange(self.repCount):
				self._executeExtended()
			self._postStep()
		else:
			for i in xrange(self.repCount):
				CPU._step(self)
			self._postStep()
			
	def _postStep(self):
		#Cleanup any member variables used during decode/processing.
		self.extWord = None
		self.zcFlag = None
		self.alFlag = None
		self.r.setAlFlag(ALFLAG_NORMAL)
		self.repCount = None
		self.multiCount = None
		self.extInstrType = None
		self.extInstrSrc = None
		self.extInstrDest = None
		CPU._postStep(self)
		
	def _constGenerator(self):
		instrSrc = self.instrSrc
		asFlag = self.asFlag
		alFlag = self.alFlag
		if instrSrc == 3 and asFlag == 0b11 and self.alFlag == ALFLAG_AWORD:
			return 0x0FFFFF
		else:
			return CPU._constGenerator(self)
		
	def _invert(self,value):
		if self.alFlag == ALFLAG_AWORD:
			return (value & 0xFFFFF) ^ 0xFFFFF
		else:
			return CPU._invert(self,value)
		
	def _MSBMask(self):
		if self.alFlag == ALFLAG_AWORD:
			return 0x80000
		else:
			return CPU._MSBMask(self)
		
	##############################################################
	# Operand methods
	#  These setup source and destination member variables
	#  for specific addressing modes.  If no exention word
	#  was used then they default to CPU behaviors.  Otherwise
	#  they extend the operands with information from the
	#  extension word.
	##############################################################
	
	def _srcRegister16(self):
		CPU._srcRegister(self)
		self.srcValue = self.srcValue & 0xFFFF
	
	def _srcImmediate(self):
		CPU._srcImmediate(self)
		if self.extInstrSrc != None:
			self.srcValue = (self.extInstrSrc << 16) | self.srcValue 

	def _srcIndirect(self):
		CPU._srcIndirect(self)
		if self.alFlag == ALFLAG_AWORD:
			#Get another word and put together the 20bit source
			highValue, highTaint = self.mem.readBW(self.bwFlag,self.srcAddr+2)
			self.srcValue = ((highValue&0xF)<<16) | self.srcValue
			self.srcTaint = highTaint | self.srcTaint
		
	def _srcIndirectAutoIncrement(self):
		CPU._srcIndirectAutoIncrement(self)
		if self.alFlag == ALFLAG_AWORD:
			#Get another word and put together the 20bit source
			lowValue = self.srcValue
			lowTaint = self.srcTaint
			CPU._srcIndirectAutoIncrement(self)
			self.srcValue = ((self.srcValue&0xF) << 16) | (lowValue & 0xFFFF)
			self.srcTaint = self.srcTaint | lowTaint
		
	def _srcAbsolute(self):
		CPU._srcAbsolute(self)
		if self.extInstrSrc != None:
			self.srcValue = (self.extInstrSrc << 16) | self.srcValue
		
	def _srcIndexed(self):
		self.srcType = ADDR_TYPE_MEM
		srcOffset, srcOffsetTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		if self.extInstrSrc != None and self.extInstrSrc != 0:
			#TODO - This only include bits when non-zero came from 
			#Ghidra.  I don't know if this is the correct thing to do
			srcOffset = (self.extInstrSrc << 16) | srcOffset
		elif (srcOffset&0x8000):
			#Sign extend the 16bit offset
			srcOffset = 0xF0000 | srcOffset
		srcReg, srcRegTaint = self.r.getRegister(self.instrSrc,BWFLAG_WORD)
		self.srcAddr = (srcReg+srcOffset) & 0xFFFFF
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.srcAddr)
		if self.alFlag == ALFLAG_AWORD:
			#Get another word and put together the 20bit source
			highValue, highTaint = self.mem.readBW(self.bwFlag,self.srcAddr+2)
			self.srcValue = ((highValue&0xF)<<16) | self.srcValue
			self.srcTaint = highTaint | self.srcTaint
			
	def _destRegister16(self):
		CPU._destRegister(self)
		self.destType = ADDR_TYPE_REG16
		
	def _destAbsolute(self):
		CPU._destAbsolute(self)
		if self.extInstrDest != None:
			self.destAddr = (self.extInstrDest << 16) | self.destAddr
		
	def _destIndexed(self):
		destOffset, destOffsetTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		if self.extInstrDest != None and self.extInstrDest != 0:
			#TODO - This only include bits when non-zero came from 
			#Ghidra.  I don't know if this is the correct thing to do
			destOffset = (self.extInstrDest << 16) | destOffset
		elif (destOffset&0x8000):
			#Sign extend teh 16bit offset
			destOffset = 0xF000 | destOffset
		destReg, destRegTaint = self.r.getRegister(self.instrDest,BWFLAG_WORD)
		self.destType = ADDR_TYPE_MEM
		self.destAddr = (destReg + destOffset) & 0xFFFFF

	##############################################################
	# Instruction Destination Access Methods
	#  Since desniations needs to be read from and possible written
	#  to they are treated like specalty pointers.  These methods
	#  are used to dereference them.
	##############################################################
	
	def _destSet(self,value,taint):
		if self.destType == ADDR_TYPE_REG16:
			CPU._destSet(self,value&0xFFFF,taint)
		else:
			CPU._destSet(self,value,taint)
			
	def _destGet(self):
		if self.destType == ADDR_TYPE_REG16:
			value, taint = CPU._destGet(self)
			value = value & 0xFFFF
		else:
			return CPU._destGet(self)

	def _isZero(self,value):
		if self.alFlag == ALFLAG_AWORD and value & 0xFFFFF == 0:
			self.r.setRegister("Z",1)
		else:
			CPU._isZero(self,value)

	def _isNegative(self,value):
		if self.alFlag == ALFLAG_AWORD and value & 0x80000:
			self.r.setRegister("N",1)
		else:
			CPU._isNegative(self,value)
			
	def _isCarried(self,value):
		if self.alFlag == ALFLAG_AWORD and value > 0xFFFFF:
			self.r.setRegister("C",1)
		else:
			CPU._isCarried(self,value)
				
	def _isOverflowed(self,srcValue,destValue,resultValue):
		if self.alFlag == ALFLAG_AWORD:
			if (srcValue & 0x80000 == destValue & 0x80000) and (resultValue & 0x80000 != destValue & 0x80000):
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
		else:
			CPU._isOverflowed(self,srcValue,destValue,resultValue)
			
	def _isXOROverflowed(self,srcValue,destValue):
		if self.alFlag == ALFLAG_AWORD:
			if srcValue & 0x80000 != 0 and destValue & 0x80000 != 0:
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
		else:
			CPU._isXOROverflowed(self,srcValue,destValue)
			
	def _decodeExtended(self):
		#This executes the extended instructions that aren't just an 
		#extension word to a normal instruction.
		instrWord = self.instrWord
		if (instrWord>>12) == 0:
			opcode = (instrWord >> 4) & 0xF
			if opcode in self.CPUX_FORMATI:
				self.extInstrType, srcFunc, dstFunc = self.CPUX_FORMATI[opcode]
				self.alFlag = ALFLAG_AWORD
				self.r.setAlFlag(ALFLAG_AWORD)
				self.bwFlag = BWFLAG_WORD
				
				if srcFunc in [self._srcAbsolute, self._srcImmediate]:
					self.extInstrSrc  = (instrWord>>8) & 0xF
					self.instrSrc = None
				else:
					self.extInstrSrc = None
					self.instrSrc = (instrWord>>8) & 0xF
				srcFunc()
				
				if dstFunc == self._destAbsolute:
					self.extInstrDest = instrWord & 0xF
					self.instrDest = None
				else:
					self.extInstrDest = None
					self.instrDest = instrWord & 0xF
				dstFunc()
				
				return True
			opcode = ((instrWord)>>4) & 0x3F
			if opcode in self.CPUX_ROTM:
				self.extInstrType = self.CPUX_ROTM[opcode][0]
				self.rotCount = ((instrWord >> 10) & 0x3) + 1
				self.instrDest = instrWord & 0xF
				self._destRegister()
				self.alFlag = self.CPUX_ROTM[opcode][1]
				self.r.setAlFlag(self.alFlag)
				self.bwFlag = BWFLAG_WORD
				self.r.setBwFlag(self.bwFlag)
				return True
		elif (instrWord>>12) == 1:
			for i in xrange(len(self.CPUX_FORMATII)):
				shift, opcode, instrType, alFlag, srcFunc, destFunc = self.CPUX_FORMATII[i]
				if (instrWord>>shift) == opcode:
					self.extInstrType = instrType
					self.alFlag = alFlag
					self.r.setAlFlag(alFlag)
					self.bwFlag = BWFLAG_WORD
					self.r.setBwFlag(self.bwFlag)
					if srcFunc != None:
						self.extInstrSrc = instrWord&0xF
						srcFunc()
					else:
						#PUSHM/POPM have a destination but no destFunc
						self.instrDest = instrWord&0xF 
					if destFunc != None:
						destFunc()
					self.multiCount = ((instrWord>>4)&0xF) + 1
					return True
		return False
			
	def _executeExtended(self):
		if self.extInstrType == self.MOVA:
			self._destSet(self.srcValue,self.srcTaint)
		elif self.extInstrType == self.CMPA:
			destValue, destTaint = self._destGet()
			srcValue = self._invert(self.srcValue) + 1
			resultValue = srcValue + destValue
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
		elif self.extInstrType == self.ADDA:
			destValue, destTaint = self._destGet()
			resultValue = destValue + self.srcValue
			self._destSet(resultValue, self.srcTaint | destTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(self.srcValue,destValue,resultValue)
		elif self.extInstrType == self.SUBA:
			destValue, destTaint = self._destGet()
			srcValue = self._invert(self.srcValue) + 1
			resultValue = srcValue + destValue
			self._destSet(resultValue, self.srcTaint | destTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
		elif self.extInstrType == self.RRCM:
			carry = self.r.getRegister("C")
			value, taint = self._destGet()
			for i in xrange(self.rotCount):
				newCarry = value & 1
				if self.alFlag == ALFLAG_AWORD:
					value = (value >> 1) | (carry << 19)
				else:
					value = (value >> 1) | (carry << 15)
				carry = newCarry
			self._destSet(value,taint)
			self.r.setRegister("C",carry,taint)
			self._isNegative(value)
			self._isNegative(value)
			self.r.setRegister("V",0,False)
		elif self.extInstrType == self.RRAM:
			value, taint = self._destGet()
			if self.alFlag == ALFLAG_AWORD:
				msb = (value >> 19) & 1
			else:
				msb = (value >> 15) & 1
			for i in xrange(self.rotCount):
				carry = value & 1
				if self.alFlag == ALFLAG_AWORD:
					value = (value >> 1) | (msb << 19)
				else:
					value = (value >> 1) | (msb << 15)
			self._destSet(value,taint)
			self.r.setRegister("C",carry,taint)
			self._isNegative(value)
			self._isNegative(value)
			self.r.setRegister("V",0,False)
		elif self.extInstrType == self.RLAM:
			value, taint = self._destGet()
			for i in xrange(self.rotCount):
				if self.alFlag == ALFLAG_AWORD:
					carry = (value >> 19) & 1
					value = (value << 1) & 0xFFFFF
				else:
					carry = (value >> 15) & 1
					value = (value << 1) & 0xFFFF
			self._destSet(value,taint)
			self.r.setRegister("C",carry,taint)
			self._isNegative(value)
			self._isNegative(value)
			self.r.setRegister("V",0,False)
		elif self.extInstrType == self.RRUM:
			carry = self.r.getRegister("C")
			value, taint = self._destGet()
			for i in xrange(self.rotCount):
				newCarry = value & 1
				if self.alFlag == ALFLAG_AWORD:
					value = (value >> 1) | (carry << 19)
				else:
					value = (value >> 1) | (carry << 15)
				carry = newCarry
			self._destSet(value,taint)
			self.r.setRegister("C",carry,taint)
			self._isNegative(value)
			self._isNegative(value)
			self.r.setRegister("V",0,False)
		elif self.extInstrType == self.CALLA:
			#Push 20 bit PC
			pc, pcTaint = self.r.getRegister("R0")
			self.r.r.R1 = self.r.r.R1 - 2
			self.mem.writeWord(self.r.r.R1, (pc>>16)&0xF, pcTaint)
			self.r.r.R1 = self.r.r.R1 - 2
			self.mem.writeWord(self.r.r.R1, pc&0xFFFF, pcTaint) 
			#Set the PC to the destination function 
			self.r.setRegister("R0",self.srcValue,self.srcTaint)
		elif self.extInstrType == self.PUSHM:
			regidx = self.instrDest
			i = 0
			while i < self.multiCount:
				if self.alFlag == ALFLAG_AWORD:
					value, taint = self.r.getRegister(regidx)
					self.r.r.R1 = self.r.r.R1 - 2
					self.mem.writeWord(self.r.r.R1, (value>>16)&0xF, taint)
					self.r.r.R1 = self.r.r.R1 - 2
					self.mem.writeWord(self.r.r.R1, value&0xFFFF, taint)
				else:
					value, taint = self.r.getRegister(regidx)
					self.r.r.R1 = self.r.r.R1 - 2
					self.mem.writeWord(self.r.r.R1, value, taint)
				#Next Register
				regidx = regidx - 1
				i = i + 1
				#TODO - register wrap?
				if( regidx == -1 ):
					regidx = 15
		elif self.extInstrType == self.POPM:
			regidx = self.instrDest
			i = 0
			while i < self.multiCount:
				if self.alFlag == ALFLAG_AWORD:
					value, taint = self.mem.readWord(self.r.r.R1)
					self.r.r.R1 = self.r.r.R1 + 2
					valueUpper, upperTaint = self.mem.readWord(self.r.r.R1)
					self.r.r.R1 = self.r.r.R1 + 2
					value = ((valueUpper&0xF) << 16) | (value & 0xFFFF)
					taint = upperTaint | taint
					self.r.setRegister(regidx, value, taint)
				else:
					value, taint = self.mem.readWord(self.r.r.R1)
					self.r.r.R1 = self.r.r.R1 + 2
					self.r.setRegister(regidx, value, taint)
				#Next Register
				regidx = regidx + 1
				i = i + 1
				#TODO - register wrap?
				if( regidx == 16 ):
					regidx = 0
