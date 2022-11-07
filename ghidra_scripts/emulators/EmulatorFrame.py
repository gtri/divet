from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import Timer
from java.awt.event import ActionListener
from java.awt.event import WindowListener
from javax.swing import JFileChooser
from java.io import File
from javax.swing import JSplitPane
from javax.swing import JScrollPane
from java.lang import String
from javax.swing import JLabel
from java.awt import BorderLayout
from javax.swing import JMenuBar
from javax.swing import JMenu
from javax.swing import JMenuItem
from java.awt.event import KeyEvent

from MemoryPanel import MemoryPanel
from RegistersPanel import RegistersPanel
from BreakConditions import BreakConditions
from BreakPanel import BreakPanel
from EmulationControl import EmulationControl
from ScriptEngine import ScriptEngine
from ScriptingManagerPanel import ScriptingManagerPanel
from EmulationLogger import EmulationLogger

from DisassemblePcode import PcodeFrame
from FunctionCallVisualization import TraceFrame

class EmulatorFrameListener(WindowListener):
	def __init__(self,emuFrame):
		self.emuFrame = emuFrame
	def windowActivated(self,evt):
		pass
	def windowClosed(self,evt):
		pass
	def windowClosing(self,evt):
		self.emuFrame.control.stop()
	def windowDeactivated(self,evt):
		pass
	def windowDeiconified(self,evt):
		pass
	def windowIconified(self,evt):
		pass
	def windowOpened(self,evt):
		pass

class EmulatorFrame(JFrame):
	def __init__(self, title, cpu, regs, mem, ghidraState=None, size=(1024, 768)):
		JFrame.__init__(self, title, size=size)
		self.addWindowListener(EmulatorFrameListener(self))
		
		if ghidraState != None:
			ghidraProgram = ghidraState.getCurrentProgram()
		else:
			ghidraProgram = None
		self.ghidraState = ghidraState
		self.regs = regs
		brk = BreakConditions(regs,mem,ghidraProgram)
		self.logger = EmulationLogger(regs,mem)
		mem.setLogger(self.logger)
		self.control = EmulationControl(cpu,regs,mem,brk,self.logger)
		self.control.setStepCallback( self.updateUI )
		self.control.setStopCallback( self.updateUI )
		self.lastConfigPath = None
		self.lastTracePath  = None
		self.lastStatePath  = None
		
		menuBar = JMenuBar()
		self.setJMenuBar(menuBar)
		
		fileMenu = JMenu("File")
		fileMenu.setMnemonic(KeyEvent.VK_F)
		fileMenu.add( JMenuItem("Save Config",KeyEvent.VK_S,actionPerformed=self.saveConfig) )
		fileMenu.add( JMenuItem("Load Config",KeyEvent.VK_L,actionPerformed=self.loadConfig) )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Start Trace",KeyEvent.VK_T,actionPerformed=self.startTrace) )
		fileMenu.add( JMenuItem("Stop Trace" ,KeyEvent.VK_P,actionPerformed=self.stopTrace) )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Save State" ,KeyEvent.VK_V,actionPerformed=self.saveState) )
		fileMenu.add( JMenuItem("Load State" ,KeyEvent.VK_D,actionPerformed=self.loadState) )
		menuBar.add(fileMenu)
		
		visMenu = JMenu("Visualize")
		visMenu.setMnemonic(KeyEvent.VK_V)
		visMenu.add( JMenuItem("Disassemble Pcode",KeyEvent.VK_P,actionPerformed=self.launchPcode) )
		visMenu.add( JMenuItem("Function Call Visualization",KeyEvent.VK_P,actionPerformed=self.launchFuncCallVis) )
		menuBar.add(visMenu)
		
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
		
		topLeftPanel = JPanel()
		topLeftPanel.setLayout( BoxLayout(topLeftPanel,BoxLayout.Y_AXIS) )
		self.regPanel = RegistersPanel(regs, ghidraState)
		topLeftPanel.add(JScrollPane(self.regPanel))

		ctrlPanel = JPanel()
		ctrlPanel.setLayout( BoxLayout(ctrlPanel, BoxLayout.X_AXIS) )
		ctrlPanel.add( JButton("Step", actionPerformed=self.step) )
		ctrlPanel.add( JButton("Cont", actionPerformed=self.cont) )
		ctrlPanel.add( JButton("Break", actionPerformed=self.brk) )
		ctrlPanel.add( JButton("UnStep", actionPerformed=self.unstep) )
		self.signalCombo = JComboBox(cpu.getSignals())
		self.signalCombo.setEditable(False)
		self.signalCombo.setMaximumSize( self.signalCombo.getPreferredSize() )
		ctrlPanel.add(self.signalCombo)
		ctrlPanel.add( JButton("Signal", actionPerformed=self.signal) )
		topLeftPanel.add( ctrlPanel )

		self.brkPanel = BreakPanel(brk)
		
		leftPanel = JSplitPane(JSplitPane.VERTICAL_SPLIT,topLeftPanel,JScrollPane(self.brkPanel))
		leftPanel.setDividerLocation(415)

		rightPanel = JPanel()
		rightPanel.setLayout( BoxLayout(rightPanel,BoxLayout.Y_AXIS) )
		self.memPanel = MemoryPanel(mem,ghidraProgram)
		rightPanel.add( self.memPanel )

		bottomPanel = JPanel()
		bottomPanel.setLayout( BoxLayout(bottomPanel,BoxLayout.Y_AXIS) )
		scriptEngine = ScriptEngine(cpu,regs,mem,brk,self.control,self.logger,ghidraProgram,self.updateUI,self.memPanel)
		self.scriptMgr = ScriptingManagerPanel(scriptEngine)
		bottomPanel.add(self.scriptMgr)
		
		topPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,leftPanel,rightPanel)
		topPane.setDividerLocation(512)
		topPane.setResizeWeight(0.5)
		outerPane = JSplitPane(JSplitPane.VERTICAL_SPLIT,topPane,bottomPanel)
		outerPane.setDividerLocation(540)
		outerPane.setResizeWeight(1)
		self.add(outerPane)

		self.setVisible(True)
		
	def updateUI(self):
		self.regPanel.updateRegisters()
		self.memPanel.updateMemory()
		self.brkPanel.updateBreakConditions()
		
	def step(self,e=None):
		self.control.step()
		self.updateUI()
			
	def unstep(self, e):
		self.control.unstep()
		self.updateUI()

	def cont(self, e):
		self.control.run()
			
	def brk(self, e):
		self.control.stop()
		#self.updateUI() will be called as a callback

	def signal(self,e):
		signalName  = self.signalCombo.getSelectedItem()
		self.control.signal(signalName)
		self.updateUI()

	def saveConfig(self, e):
		dlg = JFileChooser()
		if self.lastConfigPath != None:
			dlg.setSelectedFile(File(self.lastConfigPath))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.lastConfigPath = path
			fp = open(path, "wb")
			self.regPanel.saveFile(fp)
			self.memPanel.saveFile(fp)
			self.brkPanel.saveFile(fp)
			fp.close()
			
	def loadConfig(self, e):
		dlg = JFileChooser()
		if self.lastConfigPath != None:
			dlg.setSelectedFile(File(self.lastConfigPath))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.lastConfigPath = path
			fp = open(path, "rb")
			self.regPanel.loadFile(fp)
			self.regPanel.updateRegisters()
			self.memPanel.loadFile(fp)
			self.memPanel.updateMemory()
			self.brkPanel.loadFile(fp)
			fp.close()
			
	def startTrace(self, e):
		dlg = JFileChooser()
		if self.lastTracePath != None:
			dlg.setSelectedFile(File(self.lastTracePath))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.lastTracePath = path
			fp = open(path, "wb")
			self.logger.startLogging(fp)
			
	def stopTrace(self,e):
		self.logger.stopLogging()

	def saveState(self, e):
		dlg = JFileChooser()
		if self.lastStatePath != None:
			dlg.setSelectedFile(File(self.lastStatePath))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.lastStatePath = path
			fp = open(path, "wb")
			self.control.saveState(fp)
			fp.close()
	
	def loadState(self, e):
		dlg = JFileChooser()
		if self.lastStatePath != None:
			dlg.setSelectedFile(File(self.lastStatePath))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.lastStatePath = path
			fp = open(path, "rb")
			self.control.loadState(fp)
			fp.close()
			self.updateUI()
			

	def launchPcode(self, e):
		if self.ghidraState != None:
			frame = PcodeFrame(self.ghidraState,self.regs.getProgramCounter())
			frame.show()
		
	def launchFuncCallVis(self, e):
		frame = TraceFrame(self.ghidraState)
		if self.lastTracePath != None:
			frame.openTrace(self.lastTracePath)
		frame.show()