from EmulatedMemory import AREAD,AWRITE,AUNDO

class EmulationLogger:
	def __init__(self,regs,mem):
		self.regs = regs
		self.mem  = mem
		self.fp = None
		self.stepCount = 0
	
	def startLogging(self, fp, stepCount=None):
		self.fp = fp
		if stepCount != None:
			self.stepCount = stepCount
		else:
			self.stepCount = 0
		
	def stopLogging(self):
		if self.fp != None:
			self.fp.close()
			self.fp = None
		
	def logSignal(self,signalName):
		if self.fp == None:
			return
		self.fp.write("SIGNAL,%s\n"%(signalName))
		
	def logPreStep(self):
		if self.fp == None:
			return
		addressStr = self.mem.getAddressString(self.regs.getProgramCounter())
		self.fp.write("STEP,%d,%s\n"%( self.stepCount,addressStr) )

	def logPostStep(self):
		if self.fp == None:
			return
		self.stepCount = self.stepCount + 1
		
	def logPreUnstep(self):
		if self.fp == None:
			return
		self.fp.write("UNSTEP\n")

	def logPostUnstep(self):
		if self.fp == None:
			return
		self.stepCount = self.stepCount - 1
		
	def logMemoryAccess(self,bankName,accessType,address,value,tainted):
		if self.fp == None:
			return
		if accessType == AREAD:
			accessStr = "R"
		elif accessType == AWRITE:
			accessStr = "W"
		elif accessType == AUNDO:
			accessStr = "U"
		else:
			accessStr = "?"
		addressStr = self.mem.getAddressString(address)
		valueStr = self.mem.getValueString(value)
		if tainted:
			taintedStr = "T"
		else:
			taintedStr = "U"
		self.fp.write("%s,%s,%s,%s,%s\n"%(bankName,accessStr,addressStr,valueStr,taintedStr))

	def logMemoryUndoAccess(self,*args):
		if self.fp == None:
			return
		self.fp.write("UNDO,")
		self.logMemoryAccess(*args)
		
	def logComment(self,comment):
		if self.fp == None:
			return
		self.fp.write("#%s\n"%comment)
		