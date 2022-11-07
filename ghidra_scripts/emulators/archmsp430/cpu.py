import struct

BWFLAG_BYTE = 1
BWFLAG_WORD = 0

ADDR_TYPE_REG = 0
ADDR_TYPE_MEM = 1

class LittleEndianMemoryWrapper:
	def __init__(self,mem):
		self.mem = mem
		
	def readWord(self,address):
		return self.mem.readWord(address)
		
	def readBW(self,bwFlag,address):
		if bwFlag == BWFLAG_BYTE:
			return self.mem.readByte(address)
		elif bwFlag == BWFLAG_WORD:
			return self.mem.readWord(address)
			
	def writeWord(self,address,value,taint):
		self.mem.writeWord(address,value,taint)

	def writeBW(self,bwFlag,address,value,taint):
		if bwFlag == BWFLAG_BYTE:
			self.mem.writeByte(address,value,taint)
		elif bwFlag == BWFLAG_WORD:
			self.mem.writeWord(address,value,taint)

class Registers:
	flags = {"C":1,
					 "Z":2,
					 "N":4,
					 "GIE":8,
					 "CPUOFF":16,
					 "OSCOFF":32,
					 "SCG0":64,
					 "SCG1":128,
					 "V":256}
	regs = ["R0","R1","R2","R3","R4","R5","R6","R7","R8","R9","R10","R11","R12","R13","R14","R15"]
	regtaints = ["R0_taint","R1_taint","R2_taint","R3_taint","R4_taint","R5_taint","R6_taint","R7_taint","R8_taint","R9_taint","R10_taint","R11_taint","R12_taint","R13_taint","R14_taint","R15_taint"]

	
	def __init__(self):
		self.reset()
		
	def reset(self):
		for regname in self.regs:
			setattr(self,regname,0)
			setattr(self,"%s_taint"%regname,0)
		self.R1 = 0xFFFA

	def getRegistersDefinition(self):
		return [
		["Special",[["R0","PC/R0",16],["R1","SP/R1",16]]],
		["Flags/R3",[["V","oVerflow",1],["SCG1","SysClkGen1",1],["SCG0","SysClkGen2",1],["OSCOFF","OscOff",1],["CPUOFF","CPU Off",1],["GIE","General Int Enable",1],["N","Negative",1],["Z","Zero",1],["C","Carry",1]]],
		["General",[["R4","R4",16],["R5","R5",16],["R6","R6",16],["R7","R7",16],["R8","R8",16],["R9","R9",16],["R10","R10",16],["R11","R11",16],["R12","R12",16],["R13","R13",16],["R14","R14",16],["R15","R15",16]]]
		]

	def getRegister(self,regname):
		if type(regname) == int:
			regname = self.regs[regname]
		regname = regname.upper()
			
		if regname in self.flags:
			value = bool(self.R3 & self.flags[regname])
			taint = self.R3_taint
		else:
			value = getattr(self,regname,0)
			taint = getattr(self,"%s_taint"%regname,0)
			
		return value,taint
			
	def setRegister(self,regname,value,taint=0):
		if type(regname) == int:
			regname = self.regs[regname]
		regname = regname.upper()

		if regname in self.flags:
			if value:
				self.R3 = self.R3 | self.flags[regname]
			else:
				self.R3 = self.R3 & (0xFFFF ^ self.flags[regname])
			self.R3_taint = self.R3_taint | taint
		else:
			setattr(self,regname,value)
			setattr(self,"%s_taint"%regname,taint)
			
		if regname == "R0" and (self.R0 & 1) != 0:
			raise ValueError,"R0/PC must be even" 
		
	def getState(self):
		values = [getattr(self,regname,0) for regname in self.regs]+[getattr(self,"%s_taint" % regname,0) for regname in self.regs]
		return struct.pack(">HHHHHHHHHHHHHHHHIIIIIIIIIIIIIIII",*values)
		
	def setState(self,state):
		self.R0, self.R1, self.R2, self.R3, self.R4, self.R5, self.R6, self.R7, self.R8, self.R9, self.R10, self.R11, self.R12, self.R13, self.R14, self.R15, self.R0_taint, self.R1_taint, self.R2_taint, self.R3_taint, self.R4_taint, self.R5_taint, self.R6_taint, self.R7_taint, self.R8_taint, self.R9_taint, self.R10_taint, self.R11_taint, self.R12_taint, self.R13_taint, self.R14_taint, self.R15_taint = struct.unpack(">HHHHHHHHHHHHHHHHIIIIIIIIIIIIIIII",state)
		if (self.R0 & 1) != 0:
			raise ValueError,"R0/PC must be even" 
		
	def getProgramCounter(self):
		return self.R0

class FlaggedRegistersWrapper:
	def __init__(self,registers):
		self.r = registers
		self.bwFlag = BWFLAG_WORD

	def setBwFlag(self,bwFlag=BWFLAG_WORD):
		self.bwFlag = bwFlag

	def getRegister(self,regname,bwFlag=None):
		value, taint = self.r.getRegister(regname)
		if bwFlag == None:
			bwFlag = self.bwFlag
		if bwFlag == BWFLAG_BYTE:
			value = value & 0xFF
		elif bwFlag == BWFLAG_WORD:
			value = value & 0xFFFF
		else:
			raise ValueError,"B/W Flag is invalid: %d" % bwFlag
		return value, taint
			
	def setRegister(self,regname,value,taint=0,bwFlag=None):
		if bwFlag == None:
			bwFlag = self.bwFlag
		if bwFlag == BWFLAG_BYTE:
			value = value & 0xFF
		elif bwFlag == BWFLAG_WORD:
			value = value & 0xFFFF
		else:
			raise ValueError,"B/W Flag is invalid: %d" % bwFlag
		self.r.setRegister(regname,value,taint)
		
	def reset(self):
		self.r.reset()
		self.bwFlag = BWFLAG_WORD

class CPU:
	signalNames = ["RESET","SysNMI","UsrNMI",
		"INT12","INT11","INT10","INT9","INT8","INT7",
		"INT6","INT5","INT4","INT3","INT2","INT1","INT0"]
	
	def __init__(self,registers,memory):
		self.r = FlaggedRegistersWrapper(registers)
		self.mem = LittleEndianMemoryWrapper(memory)
		#_postStep will clean-up any intra-step state variables
		self._postStep()

	def getSignals(self):
		return self.signalNames
		
	def signal(self,signalName):
		try:
			inverse_priority = self.signalNames.index(signalName)
		except ValueError:
			return
		if inverse_priority > 2:
			gie, gieTant = self.r.getRegister("GIE")
			if not gie:
				return
		vectorAddress = 0xFFFE - (2*inverse_priority)
		if inverse_priority != 0: #Not RESET
			#Push PC and SR onto stack
			self.interruptPush()
			#Clear SR
			self.r.setRegister("R3",0,0)
			
			#Goto the handler
			pc, pcTaint = self.mem.readWord(vectorAddress)
			self.r.setRegister("R0",pc,pcTaint)
		else: #RESET
			self.reset()

	def reset(self):
		self.r.reset()
		pc, taint = self.mem.readWord(0xFFFE)
		self.r.setRegister("R0",pc,taint)

	def interruptPush(self):
		pc, pcTaint = self.r.getRegister("R0")
		sr, srTaint = self.r.getRegister("R3")
		self.r.r.R1 = self.r.r.R1 - 2
		self.mem.writeWord(self.r.r.R1, pc, pcTaint)
		self.r.r.R1 = self.r.r.R1 - 2
		self.mem.writeWord(self.r.r.R1, sr, srTaint)
	
	def interruptPop(self):
		pc, pcTaint = self.mem.readWord(self.r.r.R1)
		self.r.r.R1 = self.r.r.R1 + 2
		sr, srTaint = self.mem.readWord(self.r.r.R1)
		self.r.r.R1 = self.r.r.R1 + 2
		self.r.setRegister("R0",pc,pcTaint)
		self.r.setRegister("R3",sr,srTaint)
	
	def step(self):
		self._preStep()
		self._step()
		self._postStep()
	
	def _preStep(self):
		#Read the 16 bit base instruction word from memory
		self.instrWord, instrTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
	
	def _step(self):
		# 1)Determine what format of instruction this is.
		# 2)Call the format specific decode method
		#    This decodes the 16 bit base instruction word, and sets up 
		#    member variables for each field
		# 3)Call the decode specific opers method to setup the source and destination
		#    This uses the member variables from step 1 to determine the
		#    addressing mode and sets up member variables for the source and
		#    destination of the instruction
		# 4)Call the format specific execute function to do the calculations
		#    This reads what is needed from the source and destination, does
		#    the instruction and writes out the results
		instrWord = self.instrWord
		formatId = (instrWord >> 12)&0xFF
		if formatId == 1:
			self._decodeFormatII()
			self._decodeOpersFormatII()
			self._executeFormatII()
		elif formatId == 2 or formatId == 3:
			self._decodeFormatIII()
			self._decodeOpersFormatIII()
			self._executeFormatIII()
		elif formatId >= 4:
			self._decodeFormatI()
			self._decodeOpersFormatI()
			self._executeFormatI()
		else:
			raise ValueError,"Illegal instruction before %08X"%self.r.r.R0
			
	def _postStep(self):
		#Clear out all of the member variables
		#
		self.instrWord = None
		self.opcode = None
		self.instrSrc = None
		self.asFlag   = None
		self.instrSrc = None
		self.instrDest = None
		self.adFlag =  None
		self.bwFlag = None
		self.srcType = None
		self.srcAddr = None
		self.srcValue = None
		self.destType = None
		self.destValue = None
			
	def _constGenerator(self):
		instrSrc = self.instrSrc
		asFlag = self.asFlag
		bwFlag = self.bwFlag
		if instrSrc == 2:
			if asFlag == 0b10:
				return 4
			elif asFlag == 0b11:
				return 8
		elif instrSrc == 3:
			if asFlag == 0b00:
				return 0
			elif asFlag == 0b01:
				return 1
			elif asFlag == 0b10:
				return 2
			elif asFlag == 0b11:
				if bwFlag == BWFLAG_BYTE:
					return 0x0FF
				else: #bwFlag == BWFLAG_WORD
					return 0x0FFFF
		raise ValueError,"Illegal constant generation @ %08X"%self.r.pc
	
	def _invert(self,value):
		if self.bwFlag == BWFLAG_BYTE:
			return (value&0xFF) ^ 0xFF
		else: #self.bwFlag == BWFLAG_WORD
			return (value&0xFFFF) ^ 0xFFFF
	
	def _MSBMask(self):
		if self.bwFlag == BWFLAG_BYTE:
			return 0x80
		else: #self.bwFlag == BWFLAG_WORD
			return 0x8000
	
	##############################################################
	# Operand methods
	#  These setup source and destination member variables
	#  for specific addressing modes.
	##############################################################
	
	def _srcRegister(self):
		self.srcType = ADDR_TYPE_REG
		self.srcAddr = self.instrSrc
		self.srcValue, self.srcTaint = self.r.getRegister(self.instrSrc)
		
	def _srcImmediate(self):
		self.srcType = ADDR_TYPE_MEM
		self.srcAddr = self.r.r.R0
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.r.r.R0)
		self.r.r.R0 += 2

	def _srcIndirect(self):
		self.srcType = ADDR_TYPE_MEM
		self.srcAddr, srcAddrTaint = self.r.getRegister(self.instrSrc,BWFLAG_WORD)
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.srcAddr)
		
	def _srcIndirectAutoIncrement(self):
		self.srcType = ADDR_TYPE_MEM
		self.srcAddr, srcAddrTaint = self.r.getRegister(self.instrSrc,BWFLAG_WORD)
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.srcAddr)
		if self.bwFlag == BWFLAG_BYTE:
			self.r.setRegister(self.instrSrc,self.srcAddr+1,srcAddrTaint,BWFLAG_WORD)
		else: #self.bwFlag == BWFLAG_WORD
			self.r.setRegister(self.instrSrc,self.srcAddr+2,srcAddrTaint,BWFLAG_WORD)
		
	def _srcSymbolic(self):
		self.srcType = ADDR_TYPE_MEM
		self.srcAddr = self.r.r.R0
		srcOffset, srcOffsetTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		srcReg, srcRegTaint = self.r.getRegister(self.instrSrc,BWFLAG_WORD)
		self.srcValue = srcReg + srcOffset - 2
		self.srcTaint = srcOffsetTaint | srcRegTaint
		
	def _srcAbsolute(self):
		self.srcType = ADDR_TYPE_MEM
		self.srcAddr, srcAddrTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.srcAddr)
		
	def _srcIndexed(self):
		self.srcType = ADDR_TYPE_MEM
		srcOffset, srcOffsetTaint = self.mem.readWord(self.r.r.R0)
		#if (srcOffset&0x8000):
		#	signedOffset = -((srcOffset-1)^0xFFFFF)
		#else:
		#	signedOffset = srcOffset
		self.r.r.R0 += 2
		srcReg, srcRegTaint = self.r.getRegister(self.instrSrc,BWFLAG_WORD)
		self.srcAddr = (srcReg+srcOffset)&0xFFFF
		self.srcValue, self.srcTaint = self.mem.readBW(self.bwFlag,self.srcAddr)

	def _destRegister(self):
		self.destType = ADDR_TYPE_REG
		self.destAddr = self.instrDest
		
	def _destSymbolic(self):
		destOffset, destOffsetTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		destReg, destRegTaint = self.r.getRegister(self.instrDest,BWFLAG_WORD)
		self.destType = ADDR_TYPE_MEM
		self.destAddr = destReg + destOffset - 2;
		
	def _destAbsolute(self):
		self.destType = ADDR_TYPE_MEM
		self.destAddr, destAddrTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		
	def _destAbsolute(self):
		self.destType = ADDR_TYPE_MEM
		self.destAddr, destAddrTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		
	def _destIndexed(self):
		destOffset, destOffsetTaint = self.mem.readWord(self.r.r.R0)
		self.r.r.R0 += 2
		#if (destOffset&0x8000):
		#	signedOffset = -((destOffset-1)^0xFFFFF)
		#else:
		#	signedOffset = destOffset
		destReg, destRegTaint = self.r.getRegister(self.instrDest,BWFLAG_WORD)
		self.destType = ADDR_TYPE_MEM
		self.destAddr = (destReg + destOffset) & 0xFFFF
	

	##############################################################
	# Instruction Destination Access Methods
	#  Since desniations needs to be read from and possible written
	#  to they are treated like specalty pointers.  These methods
	#  are used to dereference them.
	##############################################################
	
	def _destSet(self,value,taint):
		if self.destType == ADDR_TYPE_REG:
			self.r.setRegister(self.destAddr,value,taint)
		elif self.destType == ADDR_TYPE_MEM:
			self.mem.writeBW(self.bwFlag,self.destAddr,value,taint)
			
	def _destGet(self):
		if self.destType == ADDR_TYPE_REG:
			destValue, destTaint = self.r.getRegister(self.destAddr)
		elif self.destType == ADDR_TYPE_MEM:
			destValue, destTaint = self.mem.readBW(self.bwFlag,self.destAddr)
		else:
			raise ValueError,"Unknown address type"
		return destValue, destTaint
		
		
	##############################################################
	# Condition Flag calculators
	##############################################################
		
	def _isZero(self,value):
		if (self.bwFlag == BWFLAG_BYTE and value & 0xFF == 0) or (self.bwFlag == BWFLAG_WORD and value & 0xFFFF == 0):
			self.r.setRegister("Z",1)
		else:
			self.r.setRegister("Z",0)
			
	def _isNegative(self,value):
		if (self.bwFlag == BWFLAG_BYTE and value & 0x80) or (self.bwFlag == BWFLAG_WORD and value & 0x8000):
				self.r.setRegister("N",1)
		else:
			self.r.setRegister("N",0)
			
	def _isCarried(self,value):
		if (self.bwFlag == BWFLAG_BYTE and value > 0xFF) or (self.bwFlag == BWFLAG_WORD and value > 0xFFFF): 
			self.r.setRegister("C",1)
		else:
			self.r.setRegister("C",0)
				
	def _isOverflowed(self,srcValue,destValue,resultValue):
		if self.bwFlag == BWFLAG_BYTE:
			if (srcValue & 0x80 == destValue & 0x80) and (resultValue & 0x80 != destValue & 0x80):
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
		elif self.bwFlag == BWFLAG_WORD:
			if (srcValue & 0x8000 == destValue & 0x8000) and (resultValue & 0x8000 != destValue & 0x8000):
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
				
	def _isXOROverflowed(self,srcValue,destValue):
		if self.bwFlag == BWFLAG_BYTE:
			if srcValue & 0x80 != 0 and destValue & 0x80 != 0:
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
		elif self.bwFlag == BWFLAG_WORD:
			if srcValue & 0x8000 != 0 and destValue & 0x8000 != 0:
				self.r.setRegister("V",1)
			else:
				self.r.setRegister("V",0)
		
	##############################################################
	# Format I related methods
	##############################################################
		
	def _decodeFormatI(self):
		instrWord = self.instrWord
		self.opcode = (instrWord&0xF000) >> 12
		self.instrSrc = (instrWord&0x0F00) >> 8
		self.asFlag   = (instrWord&0x0030) >> 4
		self.instrDest = (instrWord&0x000F)
		self.adFlag = (instrWord&0x0080) >> 7
		self.bwFlag = (instrWord&0x0040) >> 6
		self.r.setBwFlag(self.bwFlag)
		
	def _decodeOpersFormatI(self):
		instrSrc = self.instrSrc
		instrDest = self.instrDest
		asFlag = self.asFlag
		adFlag = self.adFlag
		bwFlag = self.bwFlag
		
		self.r.setBwFlag(bwFlag)
		
		if instrSrc == 3 or (instrSrc == 2 and asFlag > 1):
			srcConst = [self._constGenerator(),0]
		else:
			srcConst = None	
		
		# Register - Register;     Ex: MOV Rs, Rd
		# Constant Gen - Register; Ex: MOV #C, Rd /* 0 */
		if asFlag == 0 and adFlag == 0:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcRegister()
			self._destRegister()
			
		# Register - Indexed;      Ex: MOV Rs, 0x0(Rd)
		# Register - Symbolic;     Ex: MOV Rs, 0xD
		# Register - Absolute;     Ex: MOV Rs, &0xD
		# Constant Gen - Indexed;  Ex: MOV #C, 0x0(Rd) /* 0 */
		# Constant Gen - Symbolic; Ex: MOV #C, 0xD     /* 0 */
		# Constant Gen - Absolute; Ex: MOV #C, &0xD    /* 0 */
		elif asFlag == 0 and adFlag == 1:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcRegister()
			
			if instrDest == 0:
				self._destSymbolic()
			elif instrDest == 2:
				self._destAbsolute()
			else:
				self._destIndexed()

		# Indexed - Register;      Ex: MOV 0x0(Rs), Rd
		# Symbolic - Register;     Ex: MOV 0xS, Rd
		# Absolute - Register;     Ex: MOV &0xS, Rd
		# Constant Gen - Register; Ex: MOV #C, Rd      /* 1 */
		elif asFlag == 1 and adFlag == 0:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcSymbolic()
			elif instrSrc == 2: 
				self._srcAbsolute()
			else: #Source Indexed
				self._srcIndexed()
			
			self._destRegister()
			
		# Indexed - Indexed;       Ex: MOV 0x0(Rs), 0x0(Rd)
		# Symbolic - Indexed;      Ex: MOV 0xS, 0x0(Rd)
		# Indexed - Symbolic;      Ex: MOV 0x0(Rd), 0xD
		# Symbolic - Symbolic;     Ex: MOV 0xS, 0xD
		# Absolute - Indexed;      Ex: MOV &0xS, 0x0(Rd)
		# Indexed - Absolute;      Ex: MOV 0x0(Rs), &0xD
		# Absolute - Absolute;     Ex: MOV &0xS, &0xD
		# Absolute - Symbolic;     Ex: MOV &0xS, 0xD
		# Symbolic - Absolute;     Ex: MOV 0xS, &0xD
		# Constant Gen - Indexed;  Ex: MOV #C, 0x0(Rd)      /* 1 */
		# Constant Gen - Symbolic; Ex: MOV #C, 0xD          /* 1 */
		# Constant Gen - Absolute; Ex: MOV #C, &0xD         /* 1 */
		elif asFlag ==1 and adFlag == 1:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcSymbolic()
			elif instrSrc == 2:
				self._srcAbsolute()
			else:
				self._srcIndexed()
			
			if instrDest == 0:
				self._destSymbolic()
			elif instrDest == 2:
				self._destAbsolute()
			else:
				self._destIndexed()
		
		# Indirect - Register;     Ex: MOV @Rs, Rd
		# Constant Gen - Register; Ex: MOV #C, Rd  /* 2, 4 */
		elif asFlag == 2 and adFlag == 0:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcIndirect()
			
			self._destRegister()
			
		# Indirect - Indexed;      Ex: MOV @Rs, 0x0(Rd)
		# Indirect - Symbolic;     Ex: MOV @Rs, 0xD
		# Indirect - Absolute;     Ex: MOV @Rs, &0xD
		# Constant Gen - Indexed;  Ex: MOV #C, 0x0(Rd)     /* 2, 4 */
		# Constant Gen - Symbolic; Ex: MOV #C, 0xD         /* 2, 4 */
		# Constant Gen - Absolute; Ex: MOV #C, &0xD        /* 2, 4 */
		elif asFlag == 2 and adFlag == 1:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcIndirect()
				
			if instrDest == 0:
				self._destSymbolic()
			elif instrDest == 2:
				self._destAbsolute()
			else:
				self._destIndexed()
		
		# Indirect Inc - Register; Ex: MOV @Rs+, Rd
		# Immediate - Register;    Ex: MOV #S, Rd
		# Constant Gen - Register; Ex: MOV #C, Rd    /* -1, 8 */
		elif asFlag == 3 and adFlag == 0:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcImmediate()
			else:
				self._srcIndirectAutoIncrement()
				
			self._destRegister()
				
		# Indirect Inc - Indexed;  Ex: MOV @Rs+, 0x0(Rd)
		# Indirect Inc - Symbolic; Ex: MOV @Rs+, 0xD
		# Indirect Inc - Absolute; Ex: MOV @Rs+, &0xD
		# Immediate - Indexed;     Ex: MOV #S, 0x0(Rd)
		# Immediate - Symbolic;    Ex: MOV #S, 0xD
		# Immediate - Absolute;    Ex: MOV #S, &0xD
		# Constant Gen - Indexed;  Ex: MOV #C, 0x0(Rd)    /* -1, 8 */
		# Constant Gen - Symbolic; Ex: MOV #C, 0xD        /* -1, 8 */
		# Constant Gen - Absolute; Ex: MOV #C, &0xD       /* -1, 8 */
		elif asFlag == 3 and adFlag == 1:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcImmediate()
			else:
				self._srcIndirectAutoIncrement()
				
			if instrDest == 0:
				self._destSymbolic()
			elif instrDest == 2:
				self._destAbsolute()
			else:
				self._destIndexed()
		
	def _executeFormatI(self):
		opcode = self.opcode
		bwFlag = self.bwFlag
		srcValue = self.srcValue
		srcTaint = self.srcTaint
		
		# MOV SOURCE, DESTINATION
		#   Ex: MOV #4, R6
		#
		# SOURCE = DESTINATION
		#
		# The source operand is moved to the destination. The source operand is 
		# not affected. The previous contents of the destination are lost.
		if opcode == 0x4:
			self._destSet(srcValue,srcTaint)
		

		# ADD SOURCE, DESTINATION 
		#   Ex: ADD R5, R4
		# 
		# The source operand is added to the destination operand. The source op
		# is not affected. The previous contents of the destination are lost.
		#
		# DESTINATION = SOURCE + DESTINATION
		#   
		# N: Set if result is negative, reset if positive
		# Z: Set if result is zero, reset otherwise
		# C: Set if there is a carry from the result, cleared if not
		# V: Set if an arithmetic overflow occurs, otherwise reset
		elif opcode == 0x5:
			destValue, destTaint = self._destGet()
			resultValue = srcValue + destValue
			resultTaint = srcTaint
			self._destSet(resultValue,resultTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
			
		# ADDC SOURCE, DESTINATION 
		#   Ex: ADDC R5, R4
		#
		# DESTINATION += (SOURCE + C)
		#
		# N: Set if result is negative, reset if positive
		# Z: Set if result is zero, reset otherwise
		# C: Set if there is a carry from the result, cleared if not
		# V: Set if an arithmetic overflow occurs, otherwise reset  
		elif opcode == 0x6:
			destValue, destTaint = self._destGet()
			carryValue, carryTaint = self.r.getRegister("C")
			srcValue = srcValue + carryValue
			resultValue = srcValue + destValue
			resultTaint = srcTaint | destTaint | carryTaint
			self._destSet(resultValue,resultTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
			
		# SUBC SOURCE, DESTINATION
		#   Ex: SUBC R4, R5
		#
		#   DST += ~SRC + C
		#
		#  N: Set if result is negative, reset if positive
		#  Z: Set if result is zero, reset otherwise
		#  C: Set if there is a carry from the MSB of the result, reset otherwise.
		#     Set to 1 if no borrow, reset if borrow.
		#  V: Set if an arithmetic overflow occurs, otherwise reset
		elif opcode == 0x7:
			destValue, destTaint = self._destGet()
			carryValue, carryTaint = self.r.getRegister("C")
			srcValue = self._invert(srcValue) + carryValue
			resultValue = srcValue + destValue
			resultTaint = srcTaint | destTaint | carryTaint
			self._destSet(resultValue,resultTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
			
		# SUB SOURCE, DESTINATION
		#   Ex: SUB R4, R5
		#
		#   DST -= SRC
		#
		#  N: Set if result is negative, reset if positive
		#  Z: Set if result is zero, reset otherwise
		#  C: Set if there is a carry from the MSB of the result, reset otherwise.
		#     Set to 1 if no borrow, reset if borrow.
		#  V: Set if an arithmetic overflow occurs, otherwise reset
		#  TODO: SUBTRACTION OVERFLOW FLAG ERROR - I don't know if this is still as error
		elif opcode == 0x8:
			destValue, destTaint = self._destGet()
			srcValue = self._invert(srcValue) + 1
			resultValue = srcValue + destValue
			resultTaint = srcTaint | destTaint
			self._destSet(resultValue,resultTaint)
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
			
		# CMP SOURCE, DESTINATION
		#
		# N: Set if result is negative, reset if positive (src >= dst)
		# Z: Set if result is zero, reset otherwise (src = dst)
		# C: Set if there is a carry from the MSB of the result, reset otherwise
		# V: Set if an arithmetic overflow occurs, otherwise reset   
		# TODO: Fix overflow error - I don't know if this is still an error
		elif opcode == 0x9:
			destValue, destTaint = self._destGet()
			srcValue = self._invert(srcValue) + 1
			resultValue = srcValue + destValue
			resultTaint = srcTaint | destTaint
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self._isOverflowed(srcValue,destValue,resultValue)
			
		# DADD SOURCE, DESTINATION
		#
		# Binary Coded Decimal (BCD) add
		# N: Set if the MSB is 1, reset otherwise
		# Z: Set if result is zero, reset otherwise
		# C: Set if the result is greater than 9999
		#    Set if the result is greater than 99
		# V: Undefined
		elif opcode == 0xA:
			destValue, destTaint = self._destGet()
			if bwFlag == BWFLAG_BYTE:
				srcValue = ((srcValue & 0x0F) >> 0)*1 + ((srcValue & 0xF0) >> 4)*10
				destValue = ((destValue & 0x0F) >> 0)*1 + ((destValue & 0xF0) >> 4)*10
			elif bwFlag == BWFLAG_WORD:
				srcValue = ((srcValue & 0x000F) >> 0)*1 + ((srcValue & 0x00F0) >> 4)*10 + ((srcValue & 0x0F00) >> 8)*100 + ((srcValue & 0xF000) >> 12)*1000
				destValue = ((destValue & 0x000F) >> 0)*1 + ((destValue & 0x00F0) >> 4)*10 + ((destValue & 0x0F00) >> 8)*100 + ((destValue & 0xF000) >> 12)*1000
			resultValue = srcValue + destValue
			resultTaint = srcTaint | destTaint
			self._isZero(resultValue)
			self._isNegative(resultValue)
			if bwFlag == BWFLAG_BYTE and result > 99:
				self.r.setRegister("C",1)
			elif bwFlag == BWFLAG_WORD and result > 9999:
				self.r.setRegister("C",1)
			if bwFlag == BWFLAG_BYTE:
				v = resultValue % 99
				n = v/10
				resultValue = (n<<4)
				v = v - n
				resultValue =  resultValue | v
			elif bwFlag == BWFLAG_WORD:
				v = resultValue % 9999
				n = v/1000
				resultValue = (n<<12)
				v = v - n
				n = v/100
				resultValue = resultValue | (n<<8)
				v = v - n
				n = v/10
				resultValue = resultValue | (n<<4)
				v = v - n
				resultValue =  resultValue | v			
			self._destSet(resultValue,resultTaint)
		
		# BIT SOURCE, DESTINATION
		#
		# N: Set if MSB of result is set, reset otherwise
		# Z: Set if result is zero, reset otherwise
		# C: Set if result is not zero, reset otherwise (.NOT. Zero)
		# V: Reset
		elif opcode == 0xB:
			destValue, destTaint = self._destGet()
			resultValue = srcValue & destValue
			self._isZero(resultValue)
			self._isNegative(resultValue)
			self._isCarried(resultValue)
			self.r.setRegister("V",0)
			
		# BIC SOURCE, DESTINATION
		#
		# No status bits affected
		elif opcode == 0xC:
			destValue, destTaint = self._destGet()
			resultValue = self._invert(srcValue) & destValue
			resultTaint = srcTaint | destTaint
			self._destSet(resultValue,resultTaint)
			
		# BIS SOURCE, DESTINATION
		elif opcode == 0xD:
			destValue, destTaint = self._destGet()
			resultValue = srcValue | destValue
			resultTaint = srcTaint | destTaint
			self._destSet(resultValue,resultTaint)
			
		# XOR SOURCE, DESTINATION
		#
		# N: Set if result MSB is set, reset if not set
		# Z: Set if result is zero, reset otherwise
		# C: Set if result is not zero, reset otherwise ( = .NOT. Zero)
		# V: Set if both operands are negative
		elif opcode == 0xE:
			destValue, destTaint = self._destGet()
			resultValue = srcValue ^ destValue
			resultTaint = srcTaint | destTaint
			self._destSet(resultValue,resultTaint)
			self._isNegative(resultValue)
			self._isZero(resultValue)
			self.r.setRegister("C",1-self.r.getRegister("Z")[0])
			self._isXOROverflowed(srcValue,destValue)
			
		# AND SOURCE, DESTINATION
		#
		#  N: Set if result MSB is set, reset if not set
		#  Z: Set if result is zero, reset otherwise
		#  C: Set if result is not zero, reset otherwise ( = .NOT. Zero)
		#  V: Reset
		elif opcode == 0xF:
			destValue, destTaint = self._destGet()
			resultValue = srcValue & destValue
			resultTaint = srcTaint | destTaint
			self._destSet(resultValue,resultTaint)
			self._isNegative(resultValue)
			self._isZero(resultValue)
			self.r.setRegister("C",1-self.r.getRegister("Z")[0])
			self.r.setRegister("V",0)
			
		else:
			raise ValueError,"Undefined opcode"
			


	##############################################################
	# Format II related methods
	##############################################################
			
	def _decodeFormatII(self):
		instrWord = self.instrWord
		self.opcode = (instrWord&0x0380) >> 7
		self.bwFlag = (instrWord&0x0040) >> 6
		self.asFlag   = (instrWord&0x0030) >> 4
		self.instrSrc = (instrWord&0x000F)
		self.r.setBwFlag(self.bwFlag)
		
	def _decodeOpersFormatII(self):
		instrSrc = self.instrSrc
		asFlag = self.asFlag
		bwFlag = self.bwFlag
		
		if instrSrc == 3 or (instrSrc == 2 and asFlag > 1):
			srcConst = [self._constGenerator(),0]
		else:
			srcConst = None
			
		# Register;     Ex: PUSH Rd */
		# Constant Gen; Ex: PUSH #C */   /* 0 */
		if asFlag == 0:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcRegister()
				
		# Indexed;      Ex: PUSH 0x0(Rs)
		# Symbolic;     Ex: PUSH 0xS
		# Absolute:     Ex: PUSH &0xS
		# Constant Gen; Ex: PUSH #C       /* 1 */
		elif asFlag == 1:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcSymbolic()
			elif instrSrc == 2:
				self._srcAbsolute()
			else:
				self._srcIndexed()
				
		# Indirect;     Ex: PUSH @Rs
		# Constant Gen; Ex: PUSH #C  /* 2, 4 */
		elif asFlag == 2:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			else:
				self._srcIndirect()

		# Indirect AutoIncrement; Ex: PUSH @Rs+
		# Immediate;              Ex: PUSH #S
		# Constant Gen;           Ex: PUSH #C    /* -1, 8 */
		elif asFlag == 3:
			if srcConst != None:
				self.srcValue, self.srcTaint = srcConst
			elif instrSrc == 0:
				self._srcImmediate()
			else:
				self._srcIndirectAutoIncrement()
				
		self.destType = self.srcType
		self.destAddr = self.srcAddr
	
	def _executeFormatII(self):
		opcode = self.opcode
		bwFlag = self.bwFlag
		srcValue = self.srcValue
		srcTaint = self.srcTaint
		
		#  RRC Rotate right through carry
		#    C -> MSB -> MSB-1 .... LSB+1 -> LSB -> C
		#  
		#  Description The destination operand is shifted right one position 
		#  as shown in Figure 3-18. The carry bit (C) is shifted into the MSB, 
		#  the LSB is shifted into the carry bit (C).
		#
		# N: Set if result is negative, reset if positive
		# Z: Set if result is zero, reset otherwise
		# C: Loaded from the LSB
		# V: Reset
		# TODO: UNDEFINED BEHAVIOR DURRING CONSTANT MANIPULATION, BROKEN
		if opcode == 0x0:
			carryValue, carryTaint = self.r.getRegister("C")
			if carryValue:
				resultValue = self._MSBMask() | (srcValue>>1)
			else:
				resultValue = srcValue>>1
			resultTaint = srcTaint | carryTaint
			self._isNegative(resultValue)
			self._isZero(resultValue)
			self.r.setRegister("C",srcValue&1)
			self.r.setRegister("V",0)
			self._destSet(resultValue,resultTaint)
			
		# SWPB Swap bytes
		# bw flag always 0 (word)
		# Bits 15 to 8 <-> bits 7 to 0
		elif opcode == 0x1:
			MSB = (srcValue&0xFF00)>>8
			LSB = (srcValue&0x00FF)
			resultValue = (LSB<<8)|MSB
			resultTaint = srcTaint
			self._destSet(resultValue,resultTaint)
			
		# RRA Rotate right arithmetic 
		#   MSB -> MSB, MSB -> MSB-1, ... LSB+1 -> LSB, LSB -> C
		# 
		# N: Set if result is negative, reset if positive
		# Z: Set if result is zero, reset otherwise
		# C: Loaded from the LSB
		# V: Reset
		elif opcode == 0x2:
			resultValue = (srcValue&self._MSBMask()) | (srcValue>>1)
			resultTaint = srcTaint
			self._isNegative(resultValue)
			self._isZero(resultValue)
			self.r.setRegister("C",srcValue&1)
			self.r.setRegister("V",0)
			self._destSet(resultValue,resultTaint)
			
		# SXT Sign extend byte to word
		#   bw flag always 0 (word)
		#
		# Bit 7 -> Bit 8 ......... Bit 15
		# 
		# N: Set if result is negative, reset if positive
		# Z: Set if result is zero, reset otherwise
		# C: Set if result is not zero, reset otherwise (.NOT. Zero)
		# V: Reset
		elif opcode == 0x3:
			if srcValue&0x80:
				resultValue = 0xF0 | srcValue
			else:
				resultValue = srcValue
			resultTaint = srcTaint
			self._isNegative(resultValue)
			self._isZero(resultValue)
			if resultValue:
				self.r.setRegister("C",0)
			else:
				self.r.setRegister("C",1)
			self.r.setRegister("V",0)
			
		# PUSH push value on to the stack
		#   
		#   SP - 2 -> SP
		#   src -> @SP
		elif opcode == 0x4:
			self.r.r.R1 = self.r.r.R1 - 2
			self.mem.writeBW(bwFlag,self.r.r.R1,srcValue,srcTaint)
			
		# CALL SUBROUTINE: 
		#     PUSH PC and PC = SRC
		elif opcode == 0x5:
			self.r.r.R1 = self.r.r.R1 - 2
			pc, pcTaint = self.r.getRegister("R0")
			self.mem.writeWord(self.r.r.R1,pc,pcTaint)
			self.r.setRegister("R0",srcValue,srcTaint)
		
		# RETI Return from interrupt: Pop SR then pop PC
		elif opcode == 0x6: 
			self.interruptPop()
			
		else:
			raise ValueError,"Undefined opcode"


	##############################################################
	# Format III related methods
	##############################################################
			
	def _decodeFormatIII(self):
		instrWord = self.instrWord
		self.cond = (instrWord & 0x1C00) >> 10
		self.instrOffset = instrWord & 0x03FF
		
	def _decodeOpersFormatIII(self):
		pass
		
	def _executeFormatIII(self):
		cond = self.cond
		instrOffset = self.instrOffset
		
		if instrOffset >> 9:
			signedOffset = ((0x3FF ^ instrOffset)+1) * -2
		else:
			signedOffset = instrOffset * 2
		
		# JNE/JNZ Jump if not equal/zero             
		#
		# If Z = 0: PC + 2 offset -> PC
		# If Z = 1: execute following instruction
		if cond == 0x0:
			zero, zeroTaint = self.r.getRegister("Z")
			if not zero:
				self.r.r.R0 = self.r.r.R0 + signedOffset
		
		# JEQ/JZ Jump is equal/zero
		# If Z = 1: PC + 2 offset -> PC
		# If Z = 0: execute following instruction
		elif cond == 0x1:
			zero, zeroTaint = self.r.getRegister("Z")
			if zero:
				self.r.r.R0 = self.r.r.R0 + signedOffset
		
		# JNC/JLO Jump if no carry/lower
		#
		#  if C = 0: PC + 2 offset -> PC
		#  if C = 1: execute following instruction
		elif cond == 0x2:
			carry, carryTaint = self.r.getRegister("C")
			if not carry:
				self.r.r.R0 = self.r.r.R0 + signedOffset
				
		# JC/JHS Jump if carry/higher or same
		#
		# If C = 1: PC + 2 offset -> PC
		# If C = 0: execute following instruction
		elif cond == 0x3:
			carry, carryTaint = self.r.getRegister("C")
			if carry:
				self.r.r.R0 = self.r.r.R0 + signedOffset
		
		# JN Jump if negative
		#
		#  if N = 1: PC + 2 * offset -> PC
		#  if N = 0: execute following instruction
		elif cond == 0x4:
			negative, negativeTaint = self.r.getRegister("N")
			if negative:
				self.r.r.R0 = self.r.r.R0 + signedOffset
				
		# JGE Jump if greater or equal (N == V)
		#
		#  If (N .XOR. V) = 0 then jump to label: PC + 2 P offset -> PC
		#  If (N .XOR. V) = 1 then execute the following instruction
		elif cond == 0x5:
			negative, negativeTaint = self.r.getRegister("N")
			overflow, overflowTaint = self.r.getRegister("V")
			if not (negative ^ overflow):
				self.r.r.R0 = self.r.r.R0 + signedOffset
				
		# JL Jump if less (N != V)  
		#
		#  If (N .XOR. V) = 1 then jump to label: PC + 2 offset -> PC
		#  If (N .XOR. V) = 0 then execute following instruction
		elif cond == 0x6:
			negative, negativeTaint = self.r.getRegister("N")
			overflow, overflowTaint = self.r.getRegister("V")
			if negative ^ overflow:
				self.r.r.R0 = self.r.r.R0 + signedOffset
				
		# JMP Jump Unconditionally
		#   
		#  PC + 2 * offset -> PC
		elif cond == 0x7:
			self.r.r.R0 = self.r.r.R0 + signedOffset
			
		else:
			raise ValueError,"Undefined jump operation"

