from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JTextArea
from javax.swing import JCheckBox
from javax.swing import Timer
from java.awt.event import WindowListener

from ghidra.app.services import CodeViewerService


class PcodeFrameListener(WindowListener):
	def __init__(self,pcodeFrame):
		self.pcodeFrame = pcodeFrame
	def windowActivated(self,evt):
		pass
	def windowClosed(self,evt):
		pass
	def windowClosing(self,evt):
		if self.pcodeFrame.updateTimer != None:
			self.pcodeFrame.updateTimer.stop()
			self.pcodeFrame.updateTimer = None
	def windowDeactivated(self,evt):
		pass
	def windowDeiconified(self,evt):
		pass
	def windowIconified(self,evt):
		pass
	def windowOpened(self,evt):
		pass

class PcodeFrame(JFrame):
	def __init__(self, ghidraState, address=None):
		JFrame.__init__(self, "Disassemble Pcode", size=(400,300))
		self.addWindowListener(PcodeFrameListener(self))
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
				
		topPanel = JPanel()
		topPanel.setLayout( BoxLayout(topPanel,BoxLayout.X_AXIS) )
		self.add(topPanel)
		self.updateCheckbox = JCheckBox("Auto-Update", False, actionPerformed=self._setAutoUpdate)
		topPanel.add(self.updateCheckbox)
		self.add(topPanel)
		
		self.textArea = JTextArea()
		self.textArea.setEditable(False)
		self.add(self.textArea)
		
		self.lastAddr = None
		self.updateTimer = None
		
		self.ghidraState = ghidraState
		
		self._go(address=address)

	def __varnodeString(self,vn):
		addr = vn.getOffset()
		size = vn.getSize()
		if vn.isConstant():
			return "%X[%d]" % (vn.getOffset(),size)
		elif vn.isRegister():
			lang = self.ghidraState.getCurrentProgram().getLanguage()
			reg = lang.getRegister(vn.getAddress(),size)
			if reg == None:
				return "Register Unknown"
			else:
				return reg.getName()
		else:
			bankName = vn.getAddress().getAddressSpace().getName()
			return "%s:%X[%d]" % (bankName,addr,size)

	def _go(self,evt=None, address=None):
		prog = self.ghidraState.getCurrentProgram()
		if address == None:
			tool = self.ghidraState.getTool()
			service = tool.getService(CodeViewerService)
			jaddr = service.getCurrentLocation().getAddress()
		else:
			jaddr = prog.getAddressFactory().getAddress("0x%X" % address)
		instr = prog.getListing().getInstructionAt(jaddr)
		
		if self.lastAddr != None and self.lastAddr.equals(jaddr):
			return
		self.lastAddr = jaddr
		
		if instr == None:
			self.textArea.setText("No Instruction")
			return
		
		pcodeops = instr.getPcode()
		self.textArea.setText("")
		
		disassText = str(prog.getListing().getInstructionAt(jaddr))
		self.textArea.append("%s\n" % disassText)
		self.textArea.append("--------------------\n")
		
		for pcodeop in pcodeops:
			opStr = pcodeop.getMnemonic()
			output = pcodeop.getOutput()
			if output == None:
				outStr = ""
			else:
				outStr = "%s = " % self.__varnodeString(output)
			inputs = pcodeop.getInputs()
			if len(inputs) == 0:
				self.textArea.append("%s%s\n" % (outStr,opStr))
			elif len(inputs) < 2:
				inStr = self.__varnodeString(inputs[0])
				self.textArea.append("%s%s %s\n" % (outStr,opStr,inStr))
			else:
				inStr1 = self.__varnodeString(inputs[0])
				inStr2 = self.__varnodeString(inputs[1])
				self.textArea.append("%s%s %s %s\n" % (outStr,inStr1,opStr,inStr2))

	def _setAutoUpdate(self,evt=None):
		if self.updateCheckbox.isSelected():
			self.updateTimer = Timer(1000,self._go)
			self.updateTimer.start()
		elif self.updateTimer != None:
			self.updateTimer.stop()
			self.updateTimer = None
