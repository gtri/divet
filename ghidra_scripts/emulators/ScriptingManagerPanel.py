from java.awt.event import ActionListener
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JFileChooser
from java.io import File
from javax.swing import JPanel
from javax.swing import JTextField
from javax.swing import JTextArea
from javax.swing import BorderFactory
from java.lang import Integer
from java.awt import Dimension
from javax.swing import JScrollPane
from java.awt.event import KeyListener

from ScriptEngine import SCRIPTTYPE_PYTHON, SCRIPTTYPE_DB

class ScriptingManagerPanel(JPanel):
	def __init__(self, scriptEngine):
		JPanel.__init__(self)
		self.engine = scriptEngine
		self.history = []
		self.historyIdx = None

		self.lastScriptPath = None
		
		self.scriptType = SCRIPTTYPE_PYTHON
		self.engine.setEngine(self.scriptType)
		
		self.setBorder(BorderFactory.createTitledBorder("Scripting"))
		self.setLayout(BoxLayout(self, BoxLayout.Y_AXIS))
		
		outPanel = JPanel()
		outPanel.setBorder(BorderFactory.createTitledBorder("Output"))
		outPanel.setLayout( BoxLayout(outPanel, BoxLayout.Y_AXIS) )
		self.outputArea = JTextArea()
		self.outputArea.setEditable(False)
		self.outputScrollPane = JScrollPane(self.outputArea)
		outPanel.add(  self.outputScrollPane )
		self.add( outPanel )
		
		inPanel = JPanel()
		inPanel.setBorder(BorderFactory.createTitledBorder("Input"))
		self.swapButton = JButton("Py",actionPerformed=self._swapScript)
		inPanel.add( self.swapButton )
		inPanel.setLayout(BoxLayout(inPanel, BoxLayout.X_AXIS))
		self.commandLine = JTextField()
		self.commandLine.addKeyListener(ScriptKeyListener(self))
		self.commandLine.setMaximumSize( Dimension(Integer.MAX_VALUE, self.commandLine.getPreferredSize().height) )
		inPanel.add(self.commandLine)
		inPanel.add(JButton("Enter", actionPerformed=self.submitCommand))
		self.fileButton = JButton("Browse", actionPerformed=self.browseFile)
		inPanel.add( self.fileButton )
		self.add( inPanel )
		
	def _swapScript(self,evt):
		if self.scriptType == SCRIPTTYPE_PYTHON:
			self.scriptType = SCRIPTTYPE_DB
			self.swapButton.setText("DB")
			self.fileButton.setEnabled(False)
		else:
			self.scriptType = SCRIPTTYPE_PYTHON
			self.swapButton.setText("Py")
			self.fileButton.setEnabled(True)
		self.engine.setEngine(self.scriptType)
			
	# Browse for a file to run a scripting and execute it
	def browseFile(self, evt):
		dlg = JFileChooser()
		if self.lastScriptPath != None:
			dlg.setSelectedFile(File(self.lastScriptPath))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getAbsolutePath()
			self.lastScriptPath = path
			script = "execfile(\"%s\")\n" % path.replace("\\","/")
			self.submitCommand(script=script)
		
	def updateOutput(self):
		self.outputArea.append( self.engine.getOutput() )
		scrollBar = self.outputScrollPane.getVerticalScrollBar()
		scrollBar.setValue(scrollBar.getMaximum())
		
	# Submit a command to be parsed
	def submitCommand(self, evt=None, script=None):
		if script == None:
			script = str(self.commandLine.getText()).strip()
		if len(script):
			self.history.append(script)
			self.history = self.history[-25:]
			self.commandLine.setText("")
			self.historyIdx = None
			self.outputArea.append(">>%s\n" % script)
			outputString = self.engine.execute(script)
			self.outputArea.append(outputString)
			scrollBar = self.outputScrollPane.getVerticalScrollBar()
			scrollBar.setValue(scrollBar.getMaximum())
	
	def prevCommand(self):
		if self.historyIdx == None:
			if len(self.history):
				self.historyIdx = len(self.history) - 1
		elif self.historyIdx > 0:
			self.historyIdx = self.historyIdx - 1
		if self.historyIdx != None:
			self.commandLine.setText(self.history[self.historyIdx])
		else:
			self.commandLine.setText("")
			
	def nextCommand(self):
		if self.historyIdx != None:
			self.historyIdx = self.historyIdx + 1
			if self.historyIdx >= len(self.history):
				self.historyIdx = None
		if self.historyIdx != None:
			self.commandLine.setText(self.history[self.historyIdx])
		else:
			self.commandLine.setText("")
	
class ScriptKeyListener(KeyListener):
	def __init__(self, panel):
		self.panel = panel
	
	def keyTyped(self, event):
		pass
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		keyCode = event.getKeyCode()
		if keyCode == event.VK_ENTER:
			self.panel.submitCommand()
		elif keyCode == event.VK_UP:
			self.panel.prevCommand()
		elif keyCode == event.VK_DOWN:
			self.panel.nextCommand()
		
	