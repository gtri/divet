from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JTextArea
from javax.swing import JTextField
from javax.swing import JButton
from java.lang import Integer
from java.awt import Dimension
from java.awt import Color
from java.awt.event import KeyListener
from java.awt.event import ActionListener
from java.awt.event import ActionListener

KEYBOARD_COL = {
	'1':0xFD,'q':0xFD,'a':0xFD,         '0':0xFD,'p':0xFD,'\n':0xFD,' ':0xFD,
	'!':0xFC,'Q':0xFC,'A':0xFC,         ')':0xFC,'P':0xFC,
	'2':0xFB,'w':0xFB,'s':0xFB,'z':0xFB,'9':0xFB,'o':0xFB,'l':0xFB,'.':0xFB,
	'@':0xFA,'W':0xFA,'S':0xFA,'Z':0xFA,'(':0xFA,'O':0xFA,'L':0xFA,'>':0xFA,
	'3':0xF7,'e':0xF7,'d':0xF7,'x':0xF7,'8':0xF7,'i':0xF7,'k':0xF7,'m':0xF7,
	'#':0xF6,'E':0xF6,'D':0xF6,'X':0xF6,'*':0xF6,'I':0xF6,'K':0xF6,'M':0xF6,
	'4':0xEF,'r':0xEF,'f':0xEF,'c':0xEF,'7':0xEF,'u':0xEF,'j':0xEF,'n':0xEF,
	'$':0xEE,'R':0xEE,'F':0xEE,'C':0xEE,'&':0xEE,'U':0xEE,'J':0xEE,'N':0xEE,
	'5':0xDF,'t':0xDF,'g':0xDF,'v':0xDF,'6':0xDF,'y':0xDF,'h':0xDF,'b':0xDF,
	'%':0xDE,'T':0xDE,'G':0xDE,'V':0xDE,'^':0xDE,'Y':0xDE,'H':0xDE,'B':0xDE,
}

KEYBOARD_ROW = {
	          'z':0xFE,'x':0xFE,'c':0xFE,'v':0xFE,
	          'Z':0xFE,'X':0xFE,'C':0xFE,'V':0xFE,
	 'a':0xFD,'s':0xFD,'d':0xFD,'f':0xFD,'g':0xFD,
	 'A':0xFD,'S':0xFD,'D':0xFD,'F':0xFD,'G':0xFD,	
	 'q':0xFB,'w':0xFB,'e':0xFB,'r':0xFB,'t':0xFB,
	 'Q':0xFB,'W':0xFB,'E':0xFB,'R':0xFB,'T':0xFB,
	 '1':0xF7,'2':0xF7,'3':0xF7,'4':0xF7,'5':0xF7,
	 '!':0xF7,'@':0xF7,'#':0xF7,'$':0xF7,'%':0xF7,
	 '0':0xEF,'9':0xEF,'8':0xEF,'7':0xEF,'6':0xEF,
	 ')':0xEF,'(':0xEF,'*':0xEF,'&':0xEF,'^':0xEF,	
	 'p':0xDF,'o':0xDF,'i':0xDF,'u':0xDF,'y':0xDF,
	 'P':0xDF,'O':0xDF,'I':0xDF,'U':0xDF,'Y':0xDF,
	'\n':0xBF,'l':0xBF,'k':0xBF,'j':0xBF,'h':0xBF,
	          'L':0xBF,'K':0xBF,'J':0xBF,'H':0xBF,
	 ' ':0x7F,'.':0x7F,'m':0x7F,'n':0x7F,'b':0x7F,
	          '>':0x7F,'M':0x7F,'N':0x7F,'B':0x7F,
}

CHARACTERSET = \
	" ??????????\"?$:?()><=+-*/;,.0123" \
	"456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
	"RNDINKEY$PI?????????????????????" \
	"????????????????????????????????"

class InputListener(KeyListener):
	def __init__(self,inputField):
		self.inputField = inputField
		self.inputBuffer = [None]
		self.inputCount = 4
	
	def hasChar(self):
		if len(self.inputBuffer): 
			return True
		return False
	
	def getChar(self):
		if len(self.inputBuffer):
			c = self.inputBuffer[0]
			self.inputCount = self.inputCount - 1
			if self.inputCount == 0:
				if self.inputBuffer[0] != None:
					self.inputBuffer = [None] + self.inputBuffer[1:]
				else:
					self.inputBuffer = self.inputBuffer[1:]
				if len(self.inputBuffer)  and self.inputBuffer[0] == None:
					self.inputCount = 4
				else:
					self.inputCount = 2
			self.updateField()
		else:
			c = None
		return c
	
	def updateField(self):
		chars = "".join([x for x in self.inputBuffer if x != None]).replace("\n","\\n")
		self.inputField.setText(chars)
	
	def pushInput(self,text):
		for c in text:
			self.inputBuffer.append(c)
		self.updateField()
	
	def keyTyped(self, event):
		c = event.getKeyChar()
		self.inputBuffer.append(c)
		self.updateField()
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		pass

class KeyboardHandler:
	def __init__(self, input):
		self.input = input
		#Break at call to KEYBOARD in DISPLAY_2
		self.bp = addBrk("BP 023E") 

	def process(self):
		if isBrk(self.bp):
			#Skip the call to KEYBOARD
			setReg("PC",getReg("PC")+3)
			
			#Setup HL to match the result from KEYBOARD
			c = self.input.getChar()
			print "Input %s : HL <= %02X %02X" % (repr(c),KEYBOARD_COL.get(c,0xFE),KEYBOARD_ROW.get(c,0xFF))
			setReg("H",KEYBOARD_COL.get(c,0xFE),taint=1)
			setReg("L",KEYBOARD_ROW.get(c,0xFF),taint=1)
			return True
		return False
				
class DisplayHandler:
	def __init__(self,terminal):
		self.terminal = terminal
		self.displayByass = []
		self.displayByass.append( addBrk("BP 0288") )
		self.displayByass.append( addBrk("BP 02AD") )
		self.waitBypass = []
		self.waitBypass.append( addBrk("BP 026A") )
		self.waitBypass.append( addBrk("BP 0216") )
		
	def _displayScreen(self):
		self.terminal.setBackground(Color.white)
		self.terminal.setForeground(Color.black)
		self.terminal.setText("")
		ptr = getWord(getSym("D_FILE"))
		if getByte(ptr) != 0x76:
			print "DISPLAY ERROR: Beginning of VRAM was not HALT(0x76)"
			return False
		ptr = ptr + 1
		#print "=============SCREEN============="
		for i in xrange(24):
			line = []
			while True:
				b = getByte(ptr)
				ptr = ptr + 1
				if b == 0x76:
					if len(line):
						print "Output: %s" % "".join(line)
					line.append("\n")
					self.terminal.append("".join(line))
					break
				line.append(CHARACTERSET[b&0x7F])
		#print "=============SCREEN============="
		return True
		
	def process(self):
		for id in self.displayByass:
			if isBrk(id):
				setReg("PC",getReg("PC")+3)
				return self._displayScreen()
		for id in self.waitBypass:
			if isBrk(id):
				setReg("PC",getReg("PC")+2)
				return True
		return False
		
class InitializationHandler:
	def __init__(self,terminal):
		self.terminal = terminal
		self.bp = {}
		self.bp[addBrk("BP 03E8")] = "1. Skipping memory check.\n"
		self.bp[addBrk("BP 0400")] = "2. Setting up VRAM.\n"
		self.bp[addBrk("BP 0918")] = "3. Intializing BASIC Engine.\n"
		
	def process(self):
		for id in self.bp:
			if isBrk(id):
				self.terminal.append(self.bp[id])
				rmBrk(id)
				del self.bp[id]
				return True
		return False
		
class ZX81Frame(JFrame):
	input_lines = [["PRINT \"1+2=\",1+2","pP1K2LP>1K2\n"],
				   ["10 PRINT \"HI\"","10pPhiP\n"],
				   ["20 GOTO 10","20g10\n"],
				   ["RUN","r\n"]]
	def __init__(self):
		JFrame.__init__(self, "Sinclair ZX81", size=(390,440))
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) ) 
		self.terminal = JTextArea()
		self.terminal.setEditable(False)
		self.terminal.setLineWrap(True)
		self.terminal.setBackground(Color.black)
		self.terminal.setForeground(Color.white)
		self.terminal.append("Press \"Cont\" to execute\n")
		self.add(self.terminal)
		
		inputPanel = JPanel()
		inputPanel.setLayout( BoxLayout(inputPanel,BoxLayout.X_AXIS) )
		userInput = JTextField()
		userInput.setMaximumSize( Dimension(Integer.MAX_VALUE, userInput.getPreferredSize().height) )
		userInput.setEditable(False)
		self.input = InputListener(userInput)
		userInput.addKeyListener(self.input)
		inputPanel.add(userInput)
		self.lineButton = JButton("Test Input", actionPerformed=self._testInput)
		inputPanel.add(self.lineButton)
		nextButton = JButton("Next", actionPerformed=self._nextInput)
		inputPanel.add(nextButton)
		self.add(inputPanel)
		
		self.test_count = -1
		self._nextInput()
		
		self.terminal.addKeyListener(self.input)
				
		setSpeed(1000)
		resetCpu()
		resetMem()
		
		if "ram" in api.mem.getBanks():
			#archpcode
			setBank("ram")
			#Modify the default "ram" and "MEM" banks so addresses wrap-around
			api.mem.addBank("ram",0,0x8000,activate=True,default=True)
			api.mem.activateBank("MEM",False)
			
			#Patch the IM instruction (Pcode can't handled it)
			setByte(0x03f6,0x00)
			setByte(0x03f7,0x00)
			
			#Set-up registers correctly
			setReg("AF",0xFFFF)
			setReg("BC",0xFFFF)
			setReg("DE",0xFFFF)
			setReg("HL",0xFFFF)
			setReg("SP",0xFFFF)
			setReg("IX",0xFFFF)
			setReg("IY",0xFFFF)
			setReg("AF_",0xFFFF)
			setReg("BC_",0xFFFF)
			setReg("DE_",0xFFFF)
			setReg("HL_",0xFFFF)
		else:
			#archz80
			setBank("MEM")
			#Modify the default "MEM" bank so addresses wrap-around
			api.mem.addBank("MEM",0,0x8000,activate=True,default=True)
		
		clrBrk()
		self.initHandler = InitializationHandler(self.terminal)
		self.keyboardHandler = KeyboardHandler(self.input)
		self.displayHandler = DisplayHandler(self.terminal)
		
		#Video Ram Watch
		DFptr = getSym("D_FILE")
		watchWord(DFptr)
		D_FILE = 0x407D
		for i in xrange(32*24+26):
			watchByte(D_FILE+i)
		
		#Last Key Watch
		watchWord(getSym("LAST_K"))
		watchByte(getSym("DBOUNCE"))
		
		#Mode and Flags
		watchWord(getSym("MODE"))
		watchWord(getSym("FLAGS"))
		watchWord(getSym("FLAGX"))
		
		#Skip the RAM Test
		setReg("PC",getSym("INITIAL"))
		
		setCB(self._processIO)
		self.setVisible(True)
	
	def _testInput(self,evt=None):
		self.input.pushInput(self.input_lines[self.test_count%len(self.input_lines)][1])
		self._nextInput()

	def _nextInput(self,evt=None):
		self.test_count = self.test_count + 1
		self.lineButton.setToolTipText(self.input_lines[self.test_count%len(self.input_lines)][0])
		
	def _processIO(self):
		if not self.isVisible():
			setCB(None)
			return False
		processed = self.initHandler.process()
		processed |= self.displayHandler.process()
		processed |= self.keyboardHandler.process()
		
		if not processed:
			setSpeed(0)
		return processed
		
frame = ZX81Frame()


