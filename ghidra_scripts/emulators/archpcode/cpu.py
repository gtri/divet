from ghidra.pcode.emulate import Emulate
from ghidra.pcode.emulate import BreakTableCallBack
from ghidra.util.task import TaskMonitor
from EmulatedMemoryState import EmulatedMemoryState

from ghidra.util.exception import CancelledException
from ghidra.pcode.error import LowlevelError
from ghidra.pcode.emulate import InstructionDecodeException
from java.lang import IllegalStateException
from java.lang import IllegalArgumentException

class CPU:
	def __init__(self,registers,ghidraState,historySize=0):
		self.regs = registers
		self.memState = EmulatedMemoryState(registers,ghidraState,historySize)
		
		self.ghidraProgram = ghidraState.getCurrentProgram()
		self.ghidraAddressFactory = self.ghidraProgram.getAddressFactory()
		ghidraLanguage = self.ghidraProgram.getLanguage()
		
		breakTable = BreakTableCallBack(ghidraLanguage)
		self.ghidraEmulate = Emulate(ghidraLanguage,self.memState,breakTable)
	
		self.contextReg = ghidraLanguage.getContextBaseRegister()
	
	def getEmulatedMemory(self):
		return self.memState.getEmulatedMemory()

	def getSignals(self):
		return ["reset"]

	def signal(self,signalName):
		if signalName == "reset":
			self.regs.reset()

	def _handleContextRegister(self):
		if self.contextReg != None:
			jAddr = self.ghidraAddressFactory.getAddress("0x%x"%self.regs.getProgramCounter())
			instr = self.ghidraProgram.getListing().getInstructionAt(jAddr)
			if instr != None:
				contextRegValue = instr.getRegisterValue(self.contextReg)
				if contextRegValue != None and contextRegValue.hasAnyValue():
					self.regs.setRegisterValue(self.contextReg.getName(),contextRegValue,0)	
				try:
					self.ghidraEmulate.setContextRegisterValue(contextRegValue)
				except IllegalStateException, err:
					raise Exception,str(err)
				except IllegalArgumentException, err:
					raise Exception,str(err)

	def step(self):
		self.memState.resetTaint()
		self.ghidraEmulate.setExecuteAddress(self.ghidraAddressFactory.getAddress("0x%x"%self.regs.getProgramCounter()))
		
		#Extract the context register from Ghidra for the next instruction
		#  Do this _before_ execution to ensure that the context register for
		#  the correct address is available in the register memory space
		self._handleContextRegister()
		
		#Execute a single instruction
		try:
			self.ghidraEmulate.executeInstruction(False,TaskMonitor.DUMMY)
		except CancelledException, err:
			self.ghidraEmulate.dispose()
			raise Exception,str(err)
		except LowlevelError, err:
			self.ghidraEmulate.dispose()
			raise Exception,str(err)
		except InstructionDecodeException, err:
			self.ghidraEmulate.dispose()
			raise Exception,str(err)
		
		#Extract the context register from Ghidra for the next instruction
		#  Do this _after_ execution so the GUI reflects what the user expects
		#  to see for the next execution step
		self._handleContextRegister()
		