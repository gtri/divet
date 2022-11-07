from javax.swing import JFrame
from javax.swing import BoxLayout
from javax.swing import JTextArea
from javax.swing import JScrollPane
from java.awt import Color
from java.awt.event import KeyListener
from java.awt.event import ActionListener

class InputListener(KeyListener):
	def __init__(self):
		self.inputBuffer =[]
	
	def hasChar(self):
		if len(self.inputBuffer): 
			return True
		return False
	
	def getChar(self):
		if len(self.inputBuffer):
			c = self.inputBuffer[0]
			self.inputBuffer = self.inputBuffer[1:]
		else:
			c = None
		return c
	
	def keyTyped(self, event):
		c = event.getKeyChar()
		self.inputBuffer.append(c)
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		pass

class Apple1Frame(JFrame):
	def __init__(self):
		JFrame.__init__(self, "Apple 1 Emulator", size=(320,240))
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
		self.input = InputListener() 
		self.terminal = JTextArea()
		self.terminal.setEditable(False)
		self.terminal.setLineWrap(True)
		self.terminal.setBackground(Color.black)
		self.terminal.setForeground(Color.green)
		self.terminal.addKeyListener(self.input)
		self.terminalPane = JScrollPane(self.terminal)
		self.add(self.terminalPane)

		resetCpu()
		
		if "RAM" in api.mem.getBanks():
			#archpcode
			setBank("RAM")
			setReg("SP",0x1FF)
		else:
			#arch6502
			setBank("MEM")
			setReg("S",0xFF)
		setReg("PC",0xE000)
		
		self.inAddr     = 0xD010
		self.inCtrlAddr = 0xD011
		self.outAddr    = 0xD0F2
		resetMem()
		clrBrk()
		clrWatch()
		
		for addr in [self.inAddr,self.inCtrlAddr,self.outAddr]:
			setMutable(addr,True)
			api.mem.setReadValues(addr,[])
			setByte(addr,0)
			watchByte(addr)
		addBrk("R %x" % self.inAddr,"Input",self._input)
		addBrk("R %x" % self.inCtrlAddr,"Input Control",self._inputCtrl)
		addBrk("W %x" % self.outAddr,"Output",self._output)
		self.setVisible(True)
	
	def _inputCtrl(self):
		unstep()
		if self.input.hasChar():
			setByte(self.inCtrlAddr,0x80)
		else:
			setByte(self.inCtrlAddr,0)
		step()
		return True
		
	def _input(self):
		unstep()
		c = self.input.getChar()
		if c != None:
			if c == "\n":
				c = "\r"
			b = ord(c.upper()) | 0x80
			setByte(self.inAddr,b,1)
		else:
			setByte(self.inAddr,0)
		step()
		return True
		
	def _output(self):
		c = getByte(self.outAddr)
		c = chr(c & 0x7F)
		if c == "\r":
			c = "\n"
		self.terminal.append(c)
		setByte(self.outAddr,0)
		
		#Autoscroll the terminal
		scrollBar = self.terminalPane.getVerticalScrollBar()
		scrollBar.setValue(scrollBar.getMaximum())
		return True
	
	def _stopOnClose(self):
		if not self.isVisible():
			setCB(None)
			return False
		return True
					
	def run(self):
		setCB(self._stopOnClose)
		run()
		
frame = Apple1Frame()
frame.run()
