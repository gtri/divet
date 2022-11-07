from javax.swing import Timer
from java.awt.event import ActionListener

import traceback
import threading

class EmulationControl:
	STOPPED  = 0
	RUNNING  = 1
	REQSTOP  = 2
	BREAKCB  = 3

	class stepListener(ActionListener):
		def __init__(self,parent):
			ActionListener.__init__(self)
			self.parent = parent

		def _stopRunning(self):
			self.parent.stepTimer.stop()
			self.parent.runState = self.parent.STOPPED
			if self.parent.stopCallback != None:
				self.parent.stopCallback()

		def actionPerformed(self,evt):
			if self.parent.runState == self.parent.REQSTOP:
				self._stopRunning()
			elif self.parent.runState == self.parent.RUNNING:
				try:
					self.parent._step()
				except Exception, err:
					self._stopRunning()
					raise err
					
				contExec = True
				if self.parent.brk.getTriggeredConditionsCount():
					contExec = False
					
				#If one or more break conditions occured then try the callback
				#to check if we should keep executing.
				if not contExec and self.parent.breakCallback != None:
					self.parent.runState = self.parent.BREAKCB
					try:
						cbResult = self.parent.breakCallback()
					except Exception, err:
						self._stopRunning()
						raise err
					self.parent.runState = self.parent.RUNNING
					if cbResult:
						contExec = True
					
				#Either stop execution or handle per-step callbacks
				if not contExec:
					self._stopRunning()
				else:
					if self.parent.stepCallback != None:
						if self.parent.cbCounter <= 0:
							self.parent.stepCallback()
							self.parent.cbCounter = self.parent.callbackSkipCount
						else:
							self.parent.cbCounter = self.parent.cbCounter - 1
				
	def __init__(self,cpu,regs,mem,breakConditions,logger):
		self.cpu = cpu
		self.regs = regs
		self.mem = mem
		self.brk = breakConditions
		self.logger = logger
		self.stepHistory = []
		self.runState = self.STOPPED
		self.stepTimer = Timer(1,self.stepListener(self))
		self.stepCallback  = None
		self.breakCallback = None
		self.stopCallback  = None
		self.callbackSkipCount = 0
		self.cbCounter = 0
	
	def setStepCallback(self,callback):
		self.stepCallback = callback
			
	def getStepCallback(self):
		return self.stepCallback
		
	def setStepCallbackSkip(self,skipCount):
		self.callbackSkipCount = skipCount
		self.cbCounter = skipCount
			
	def setBreakCallback(self,callback):
		self.breakCallback = callback
		
	def getBreakCallback(self):
		return self.breakCallback
	
	def setStopCallback(self,callback):
		self.stopCallback = callback
	
	def getStopCallback(self):
		return self.stopCallback
	
	def signal(self,signalName):
		self.logger.logSignal(signalName)
		self.cpu.signal(signalName)
	
	def step(self):
		if self.runState in [self.STOPPED,self.BREAKCB]:
			self._step()
	
	def _step(self):
		#Log any information before the step happens
		self.logger.logPreStep()
	
		#Save the pre-step information
		cpuState = self.regs.getState()
		pc = self.regs.getProgramCounter()
		self.mem.startStepRecord()
		
		#Execute a single instruction
		self.cpu.step()
		
		#Save off the pre-step cpuState
		self.stepHistory.append(cpuState)
		self.stepHistory = self.stepHistory[-1024:]
		
		#Check for break value conditions
		self.brk.checkConditions()

		#Finish up any logging that needs to be done
		#before the next thing
		self.logger.logPostStep()
		
		
	def unstep(self):
		if self.runState in [self.STOPPED,self.BREAKCB]:
			if len(self.stepHistory):
				self.logger.logPreUnstep()
				
				cpuState = self.stepHistory[-1]
				self.stepHistory = self.stepHistory[:-1]
				
				self.regs.setState(cpuState)
				self.mem.undoStep()
				self.brk.checkConditions()
				
				self.logger.logPostUnstep()
			
	def run(self):
		if self.runState == self.STOPPED:
			self.runState = self.RUNNING
			self.cbCounter = self.callbackSkipCount
			self.stepTimer.start()
	
	def stop(self):
		if self.runState == self.RUNNING:
			self.runState = self.REQSTOP
			
	def isRunning(self):
		return self.runState == self.RUNNING
		
	def saveState(self,fp):
		fp.write("[CPUState]\n")
		state = self.regs.getState()
		if sum([ord(b)&0x80 for b in state]):
			dump = "".join(["%02X" % ord(b) for b in state])
			fp.write("H%s\n" % dump)
		else:
			nl = chr(ord("\n")&0x80)
			cr = chr(ord("\r")&0x80)
			fp.write("S%s\n" % state.replace("\n",nl).replace("\r",cr))
		self.mem.saveState(fp)
		
	def loadState(self,fp):
		while True:
			line = fp.readline()
			if not len(line):
				break
			line = line.strip()
			if line[0] == "#":
				continue
			if not len(line):
				continue
			if line.strip().lower() == "[cpustate]":
				line = fp.readline()
				if line[0].upper() == "H":
					line = line[1:]
					state = "".join([chr(int(line[2*i:2*(i+1)],16)) for i in xrange(len(line)/2)])
				elif line[0].upper() == "S":
					nl = chr(ord("\n")&0x80)
					cr = chr(ord("\r")&0x80)
					state = line[1:].replace(nl,"\n").replace(cr,"\r")
				self.regs.setState(state)
				break
		self.mem.loadState(fp)
		