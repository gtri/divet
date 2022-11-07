import util
import instructions

class CPU:
	def __init__(self, regs, mem):
		self.registers = regs
		self.instructions = instructions.InstructionSet(self.registers)
		self.mem = mem
		
		self._interruptedDataByte = []
				
	def getSignals(self):
		return ["RESET","NMI","INT"]
		
	def signal(self,signalName,dataBytes=[0]):
		if signalName.upper() == "RESET":
			self.registers.reset(pinReset=True)
		elif signalName.upper() == "NMI":
			self.registers.HALT = False
			#Save IFF
			self.registers.IFF2 = self.registers.IFF
			self.registers.IFF = False
			
			#Push PC onto stacj
			self.registers.SP = util.dec16(self.registers.SP)
			self.mem.writeByte(self.registers.SP,(self.registers.PC>>8)&0xFF,self.registers.PC_taint)
			self.registers.SP = util.dec16(self.registers.SP)
			self.mem.writeByte(self.registers.SP,self.registers.PC&0xFF,self.registers.PC_taint)
			
			#Goto 66h
			self.registers.PC = 0x0066
		elif signalName.upper() == "INT":
			if self.registers.IFF:
				self.registers.HALT = False
				self.registers.IFF = False
				if self.registers.IM == 0:
					#Pull executable code from the data bus 
					self._interruptedDataByte = [b&0xFF for b in dataBytes] 
				elif self.registers.IM == 1:
					#Push PC onto stacj
					self.registers.SP = util.dec16(self.registers.SP)
					self.mem.writeByte(self.registers.SP,(self.registers.PC>>8)&0xFF,self.registers.PC_taint)
					self.registers.SP = util.dec16(self.registers.SP)
					self.mem.writeByte(self.registers.SP,self.registers.PC&0xFF,self.registers.PC_taint)
					
					#Goto 38h
					self.registers.PC = 0x0038
				elif self.registers.IM == 2:
					#Get the interupt handler table entry address
					if not len(dataBytes):
						addrLow = 0
					else:
						addrLow = dataBytes[0]
					handlerPtr = (self.registers.I << 8) | addrLow
					
					#Push the PC onto the stack
					self.registers.SP = util.dec16(self.registers.SP)
					self.mem.writeByte(self.registers.SP,(self.registers.PC>>8)&0xFF,self.registers.PC_taint)
					self.registers.SP = util.dec16(self.registers.SP)
					self.mem.writeByte(self.registers.SP,self.registers.PC&0xFF,self.registers.PC_taint)
					
					#Jump to the handler
					self.registers.PC, self.registers.PC_taint = self.mem.readWord(handlerPtr)
				else:
					raise NotImplementedError,"Mode%d Interupts are not supported by Z80" % self.registers.IM
		
	def step(self):
		ins, args = False, []
		pc = self.registers.PC
		
		if self.registers.HALT:
			return
		
		if len(self._interruptedDataByte):
			#Handle Mode0 Interrupts (which put executable code on the data bus
			while not ins:
				ins, args = self.instructions << (self._interruptedDataByte[0], False)
				self._interruptedDataByte[1:]
		else:				
			while not ins:
				ins, args = self.instructions << self.mem.readByte(self.registers.PC)
				self.registers.PC = util.inc16(self.registers.PC)
		#print( "{0:X} : {1} ".format(pc, ins.assembler(args)))
		
		#Args is the bytes that make of the instruction
		rd =	ins.get_read_list(args)
		data = [(0,False)] * len(rd)
		for idx, i in enumerate(rd):
			address = i & 0xFFFF
			if i < 0x10000:
				data[idx] = self.mem.readByte(address)
			else:
				data[idx] = self.mem.readByte(address,"IO")
		wrt = ins.execute(data, args)
		for i, value, taint in wrt:
			address = i & 0xFFFF
			if i > 0x10000:
				self.mem.write(address,value,taint,"IO")
			else:
				self.mem.write(address,value,taint)
		

