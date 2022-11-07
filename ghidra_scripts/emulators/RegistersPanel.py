from javax.swing import JPanel
from java.awt import GridLayout
from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from java.awt import Insets
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextField
from java.awt import Color
from java.awt import Dimension
from java.lang import Integer
from javax.swing import BorderFactory
from javax.swing import JTabbedPane
from java.awt.event import KeyListener

from ghidra.program.util import ProgramLocation

def pcode_dissassemble(ghidraState,addr):
	program = ghidraState.getCurrentProgram()
	lang = program.getLanguage()
	jaddr = program.getAddressFactory().getAddress("0x%X" % addr)
	instr = program.getListing().getInstructionAt(jaddr)
	
	def varnodeString(vn):
		addr = vn.getOffset()
		size = vn.getSize()
		if vn.isConstant():
			return "%X[%d]" % (vn.getOffset(),size)
		elif vn.isRegister():
			reg = lang.getRegister(vn.getAddress(),size)
			if reg == None:
				return "Register Unknown"
			else:
				return reg.getName()
		else:
			bankName = vn.getAddress().getAddressSpace().getName()
			return "%s:%X[%d]" % (bankName,addr,size)

	resultStr = ""

	if instr != None:
		resultStr = str(instr)
		resultStr = "\n".join([resultStr,"-"*len(resultStr)])
		pcodeops = instr.getPcode()
		for pcodeop in pcodeops:
			opStr = pcodeop.getMnemonic()
			output = pcodeop.getOutput()
			if output == None:
				outStr = ""
			else:
				outStr = "%s = " % varnodeString(output)
			inputs = pcodeop.getInputs()
			if len(inputs) == 0:
				resultStr = "\n".join([resultStr,"%s%s" % (outStr,opStr)])
			elif len(inputs) < 2:
				inStr = varnodeString(inputs[0])
				resultStr = "\n".join([resultStr,"%s%s %s" % (outStr,opStr,inStr)])
			else:
				inStr1 = varnodeString(inputs[0])
				inStr2 = varnodeString(inputs[1])
				resultStr = "\n".join([resultStr,"%s%s %s %s" % (outStr,inStr1,opStr,inStr2)])
		
	return resultStr

class RegistersPanel(JPanel,KeyListener):
	def __init__(self,regs,ghidraState=None):
		JPanel.__init__(self)
		self.regs = regs
		self.regsUI = {}
		self.ghidraState = ghidraState
		self.setBorder(BorderFactory.createTitledBorder("Registers"))
		self.setMaximumSize( Dimension(Integer.MAX_VALUE, 1 ) )
		self.setLayout( BoxLayout(self,BoxLayout.Y_AXIS) )
		registersDefinition = regs.getRegistersDefinition()
		cols = len(registersDefinition) * 2
		rows = max( [len(regDef) for categoryName, regDef in registersDefinition] )
		self.regPanel = JPanel()
		#self.regPanel.setLayout( GridLayout(rows + 1, cols) )
		layout = GridBagLayout()
		c = GridBagConstraints()
		c.fill = GridBagConstraints.HORIZONTAL
		c.insets = Insets(1, 2, 1, 2)
		self.regPanel.setLayout( layout )
		self.tabbedPane = JTabbedPane(JTabbedPane.TOP)
		isMainTab = False
		#Headers
		elemIdx = 0
		c.gridx = 0
		c.gridy = 0
		for categoryName, regDef in registersDefinition:
			if elemIdx > 0:
				label = JLabel("<HTML>&nbsp;<U><B>%s</B></U></HTML>" % categoryName)
				layout.setConstraints(label,c)
				self.regPanel.add( label )
			else:
				label = JLabel("<HTML><U><B>%s</B></U></HTML>" % categoryName)
				layout.setConstraints(label,c)
				self.regPanel.add( label )
			elemIdx += 1
			c.gridx = c.gridx + 1
			label = JLabel("<HTML><U><B>Values</B></U></HTML>")
			layout.setConstraints(label,c)
			self.regPanel.add( label )
			elemIdx += 1
			c.gridx = c.gridx + 1

		c.gridx = 0
		c.gridy = 1
					
		#Registers
		for row in xrange(rows):
			for categoryName,regDef in registersDefinition:
				if row < len(regDef):
					regName, regDisplayName, bitWidth = regDef[row]
					regDisplayName = regDisplayName.replace("<HTML>", "<HTML>&nbsp;")
					label = JLabel("%s" % regDisplayName)
					layout.setConstraints(label,c)
					self.regPanel.add( label )
					elemIdx += 1
					c.gridx = c.gridx + 1
					textField = JTextField("", max(bitWidth/4, 1))
					textField.addKeyListener(self)
					layout.setConstraints(textField,c)
					self.regPanel.add( textField )
					self.regsUI[regName] = [elemIdx,bitWidth]
					elemIdx += 1
					c.gridx = c.gridx + 1
				else:
					for i in xrange(2):
						panel = JPanel()
						layout.setConstraints(panel,c)
						self.regPanel.add( panel )
						c.gridx = c.gridx + 1
						elemIdx += 1
			c.gridx = 0
			c.gridy = c.gridy + 1

		self.add(self.regPanel)
		btnPanel = JPanel()
		btnPanel.setLayout( BoxLayout(btnPanel,BoxLayout.X_AXIS) )
		btnPanel.add( JLabel("Next Instr ") )
		self.nextInstr = JTextField()
		self.nextInstr.setEditable(False)
		btnPanel.add( self.nextInstr )
		btnPanel.add( JButton("Reset", actionPerformed=self._reset) )
		btnPanel.add( JButton("Update", actionPerformed=self._updateRegisters) )
		self.add( btnPanel )
		
		self._reset()
	
	def keyTyped(self, event):
		pass
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		keyCode = event.getKeyCode()
		if keyCode == event.VK_ENTER:
			self._updateRegisters()
	
	def _reset(self,e=None):
		self.regs.reset()
		self.updateRegisters()

	def _updateRegisters(self,e=None):
		regNames = self.regsUI.keys()
		for regName in regNames:
			elemIdx, bitWidth = self.regsUI[regName]
			max = (1 << bitWidth) - 1
			textInput = self.regPanel.getComponent(elemIdx).getText().upper()
			if "T" in textInput:
				taint = True
				textInput = textInput.replace("T", "").replace("[", "").replace("]", "")
			else:
				taint = False
			try:
				value = int(textInput, 16)
				error = False
			except ValueError:
				error = True
			else:
				if value < 0 or value > max:
					error = True
			if error:
				raise ValueError, "Register %s is not valid" % regName
			else:
				self.regs.setRegister(regName,value,taint)
				
		self.updateNextInstr()
			
	def updateRegisters(self):
		regNames = self.regsUI.keys()
		for regName in regNames:
			elemIdx, bitWidth = self.regsUI[regName]
			value, taint = self.regs.getRegister(regName)
			fmt = "%%s%%0%dX" % max(bitWidth/4,1)
			if taint:
				taintStr = "[T] "
			else:
				taintStr = ""
			textEdit = self.regPanel.getComponent(elemIdx)
			prevText = textEdit.getText()
			nextText = fmt % (taintStr,value)
			textEdit.setText(nextText)
			if nextText != prevText:
				textEdit.setBackground(Color.YELLOW)
			else:
				textEdit.setBackground(Color.WHITE)
		
		self.updateNextInstr()

	def updateNextInstr(self):
		if self.ghidraState != None:
			program = self.ghidraState.getCurrentProgram()
			addr = self.regs.getProgramCounter()
			jaddr = program.getAddressFactory().getAddress("0x%X" % addr)
			instr = program.getListing().getInstructionAt(jaddr)
			self.nextInstr.setText(str(instr))
			tool_tip = "<html>" + "<br>".join(pcode_dissassemble(self.ghidraState,addr).split("\n")) + "</html>"
			self.nextInstr.setToolTipText(tool_tip)
			self.ghidraState.setCurrentLocation( ProgramLocation(program,jaddr) )
		
	def saveFile(self,fp):
		fp.write("[Registers]\n")
		registersDefinition = self.regs.getRegistersDefinition()
		for categoryName, regDef in registersDefinition:
			fp.write("#%s\n" % categoryName)
			for regName, regDisplayName, bitWidth in regDef:
				fmt = "%%s: %%s%%0%dX\n" % max(bitWidth/4,1)
				value, taint = self.regs.getRegister(regName)
				if taint:
					taintStr = "t,"
				else:
					taintStr = ""
				fp.write(fmt % (regName, taintStr, value))
		fp.write("\n")
		
	def loadFile(self, fp):
		fp.seek(0)
		#Find the beginning
		ready = False
		while True:
			line = fp.readline()
			if not len(line):
				break
			line = line.strip()
			if not len(line):
				continue
			if line[0] == "#":
				continue
			if line[0] == "[":
				if line.strip().lower() == "[registers]":
					ready = True
				elif ready:
					break #Finished read section
				else:
					ready = False
				
			if ready:
				items = line.split(":")
				if len(items) == 2:
					regName = items[0].strip()
					taint = False
					value = 0
					items = items[1].split(",")
					for item in items:
						item = item.strip()
						if item.strip() == "t":
							taint = True
						else:
							if True: #try:
								value = int(item,16)
							else: #except ValueError:
								continuet
					self.regs.setRegister(regName, value, taint)
		self.updateRegisters()
