from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JButton
from javax.swing import JCheckBox
from javax.swing import JTextArea
from javax.swing.tree import TreeModel
from javax.swing.tree import TreeSelectionModel
from javax.swing import JTree
from javax.swing.event import TreeSelectionListener
from javax.swing import JFileChooser
from java.io import File
from javax.swing import JScrollPane
from javax.swing import JSplitPane
from java.awt.event import WindowListener

from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.services import GoToService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.address import AddressSpace
from java.awt import Color


class FunctionNode:
	def __init__(self,callAddress,entryAddress,funcName):
		self.callAddress = callAddress
		self.childrenAll = []
		self.children = self.childrenAll
		self.callAddress = callAddress
		self.entryAddress = entryAddress
		self.funcName = funcName
		self.tainted = False
		self.dataRecord    = []
		self.dataTainted   = AddressSet()
		self.dataUntainted = AddressSet()
		self.steps         = AddressSet()
		self.lastPC = entryAddress
		self.nextPC = entryAddress

	def setTainted(self,tainted=True):
		self.tainted = tainted

	def isTainted(self):
		return self.tainted

	def addChild(self,funcNode):
		self.children.append(funcNode)

	def addDataAccess(self,text,jAddress,tainted=False):
		self.dataRecord.append(text)
		if tainted:
			self.dataTainted.add(jAddress)
		else:
			self.dataUntainted.add(jAddress)

	def addStep(self,jAddress):
		self.steps.add(jAddress)

	def resetFilters(self):
		self.children = self.childrenAll
		for child in self.children:
			try:
				child.resetFilters()
			except RuntimeError:
				#Oops! ran out of stack
				pass

	def applyTaintedOnly(self):
		if not len(self.childrenAll):
			return self.isTainted()
		else:
			self.children = []
			for child in self.childrenAll:
				try:
					if child.applyTaintedOnly():
						self.children.append(child)
				except RuntimeError:
					#Oops! - ran out of stack
					pass
			if len(self.children):
				return True
			else:
				return False

	def toString(self):
		return str(self)

	def __repr__(self):
		return str(self)

	def __str__(self):
		if self.tainted:
			return "[T] %s [%08X => %08X]" % (self.funcName,self.callAddress,self.entryAddress)
		else:
			return "%s [%08X => %08X]" % (self.funcName,self.callAddress,self.entryAddress)


class TraceTreeModel(TreeModel):
	def __init__(self, ghidraState):
		self._root = FunctionNode(0,0,"Open Trace")
		self.listeners = []
		self.ghidraState = ghidraState

	def getChild(self,parent,idx):
		if idx < len(parent.children):
			return parent.children[idx]
		else:
			return None

	def getChildCount(self,parent):
		return len(parent.children)

	def getIndexOfChild(self,parent,child):
		try:
			idx = parent.children.index(child)
		except ValueError:
			return -1
		else:
			return idx

	def getRoot(self):
		return self._root

	def isLeaf(self,node):
		if not len(node.children):
			return True
		else:
			return False

	def addTreeModelListener(self,l):
		self.listeners.append(l)

	def removeTreeModelListener(self,l):
		try:
			idx = self.listeners.index(l)
		except ValueError:
			pass
		else:
			del self.listeners[idx]

	def valueForPathChanged(path,newValue):
		pass

	def parseTrace(self,fp):
		prog = self.ghidraState.getCurrentProgram()
		listing = prog.getListing()
		addrFactory = prog.getAddressFactory()
		nodes = []
		fp.seek(0)
		while True:
			line = fp.readline()
			if not len(line):
				break
			line = line.strip()
			if not len(line) or line[0] == "#":
				continue
			items = line.split(",")
			lineType = items[0].upper()
			if lineType == "UNSTEP":
				pass
			elif lineType == "UNDO":
				pass
			elif lineType == "SIGNAL":
				pass
			elif lineType == "STEP":
				pc = int(items[2],16)
				jAddr = addrFactory.getAddress("0x%X" % pc)

				funcObj = listing.getFunctionContaining(jAddr)
				if funcObj == None:
					funcName = "Unkown"
				else:
					funcName = funcObj.getName()

				if not len(nodes):
					#This is our root
					nodes.append(FunctionNode(pc,pc,funcName))
				if funcName == nodes[-1].funcName:
					#Assume this is just the next instruction in the same
					#function - this assumption will collapse single function
					#recursions
					nodes[-1].lastPC = pc
					nodes[-1].nextPC = pc
					nodes[-1].addStep(jAddr)
				else:
					#Search the call chain to see if we returned
					#(even in a non-standard way)
					isReturn = False
					for count in xrange(len(nodes)):
						idx = len(nodes)-1-count
						node = nodes[idx]
						if pc > node.lastPC and pc <= node.nextPC:
							#Assume this is a return
							node.addStep(jAddr)
							nodes = nodes[:idx+1]
							isReturn = True
							break

					if not isReturn:
						#Assume this is a new function call
						nodes.append(FunctionNode(nodes[-1].lastPC,pc,funcName))
						nodes[-2].addChild(nodes[-1])
						nodes[-1].addStep(jAddr)
			elif len(nodes): #Data access (only relevent after first step)
				accessType = items[1]
				isData = True
				addr = int(items[2],16)
				readWidth = len(items[3])/2
				if accessType == "R":	
					if addr >= nodes[-1].lastPC and addr <= nodes[-1].nextPC:
						isData = False
						if addr == nodes[-1].nextPC:
							nodes[-1].nextPC += readWidth
				tainted = (items[4].upper() == "T")
				if tainted == "T":
					nodes[-1].setTainted()
				if isData:
					jAddr = addrFactory.getAddress("0x%X" % addr)
					nodes[-1].addDataAccess(line,jAddr,tainted)
		if len(nodes):
			self._root = nodes[0]


	def resetFilters(self):
		self._root.resetFilters()

	def applyTaintedOnly(self):
		self._root.applyTaintedOnly()

class Highlighter:
	def __init__(self, ghidraState):
		self.ghidraState = ghidraState
		self.node = None
		
	def __del__(self):
		self.hide()
		
	def hide(self):
		if self.node != None:
			prog = self.ghidraState.getCurrentProgram()
			tool = self.ghidraState.getTool()
			service = tool.getService(ColorizingService)
			transId = prog.startTransaction("divetHideHighlight")
			service.setBackgroundColor(self.node.dataTainted, Color.WHITE)
			service.setBackgroundColor(self.node.dataUntainted, Color.WHITE)
			service.setBackgroundColor(self.node.steps, Color.WHITE)
			prog.endTransaction(transId,True)
		
	def show(self,node):
		self.hide()
		
		self.node = node
		prog = self.ghidraState.getCurrentProgram()
		tool = self.ghidraState.getTool()
		service = tool.getService(ColorizingService)
		transId = prog.startTransaction("divetShowHighlight")
		service.setBackgroundColor(self.node.dataTainted, Color.ORANGE)
		service.setBackgroundColor(self.node.dataUntainted, Color.YELLOW)
		service.setBackgroundColor(self.node.steps, Color.YELLOW)
		prog.endTransaction(transId,True)
		

class TraceFrameListener(WindowListener):
	def __init__(self,traceFrame):
		self.traceFrame = traceFrame
	def windowActivated(self,evt):
		pass
	def windowClosed(self,evt):
		pass
	def windowClosing(self,evt):
		self.traceFrame.highlighter.hide()
	def windowDeactivated(self,evt):
		pass
	def windowDeiconified(self,evt):
		pass
	def windowIconified(self,evt):
		pass
	def windowOpened(self,evt):
		pass

class TraceFrame(JFrame,TreeSelectionListener):
	def __init__(self, ghidraState):
		JFrame.__init__(self, "Function Tracer", size=(400,300))

		self.ghidraState = ghidraState
		self.lastTracePath = None

		self.addWindowListener(TraceFrameListener(self))
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )

		topPanel = JPanel()
		topPanel.setLayout( BoxLayout(topPanel,BoxLayout.X_AXIS) )
		self.add(topPanel)

		openButton = JButton("Open Trace",actionPerformed=self._openTrace)
		topPanel.add(openButton)
		self.taintedOnly = JCheckBox("Tainted Only", False, actionPerformed=self._taintedOnlyCheck)
		topPanel.add(self.taintedOnly)
		self.graph = JCheckBox("Show Graph", False, actionPerformed=self._graphCheck)
		topPanel.add(self.graph)
		self.hilight = JCheckBox("Highlight", False, actionPerformed=self._hilightCheck)
		topPanel.add(self.hilight)

		self.model = TraceTreeModel(self.ghidraState)
		self.tree = JTree(self.model)
		self.tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION)
		self.tree.addTreeSelectionListener(self)

		self.accessArea = JTextArea()
		self.accessArea.setEditable(False)

		self.highlighter = Highlighter(ghidraState)

		lowerPanel = JPanel()
		lowerPanel.setLayout( BoxLayout(lowerPanel,BoxLayout.X_AXIS) )
		self.add(lowerPanel)
		splitPanel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,JScrollPane(self.tree),JScrollPane(self.accessArea))
		splitPanel.setDividerLocation(200)
		splitPanel.setResizeWeight(1)
		lowerPanel.add(splitPanel)

	def _openTrace(self,evt):
		dlg = JFileChooser()
		if self.lastTracePath != None:
			dlg.setSelectedFile(File(self.lastTracePath))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.openTrace(path)

	def openTrace(self,path):
		fp = open(path,"rb")
		self.model.parseTrace(fp)
		fp.close()
		self.lastTracePath = path
		self._taintedOnlyCheck()
		self._graphCheck()

	def valueChanged(self,evt):
		selection = self.tree.getSelectionPath()
		if selection == None:
			self.highlighter.hide()
			return
		node = selection.getLastPathComponent()

		self.accessArea.setText("")
		for line in node.dataRecord:
			self.accessArea.append("%s\n" % line)

		if self.hilight.isSelected():
			self.highlighter.show(node)
		
		self._graphCheck(node=node)


	def _taintedOnlyCheck(self,evt=None):
		if self.taintedOnly.isSelected():
			self.model.applyTaintedOnly()
		else:
			self.model.resetFilters()
		self.tree.updateUI()

	def _graphCheck(self,evt=None,node=None):
		tool = self.ghidraState.getTool()
		provider = tool.getComponentProvider("Function Graph")
		
		if not self.graph.isSelected():
			tool.showComponentProvider(provider,False)
			return

		if node == None:
			selection = self.tree.getSelectionPath()
			if selection == None:
				tool.showComponentProvider(provider,False)
				return
			node = selection.getLastPathComponent()
			
		if True: #try:
			prog = self.ghidraState.getCurrentProgram()
			listing = prog.getListing()
			tool = self.ghidraState.getTool()
			gotoService = tool.getService(GoToService)
			provider = tool.getComponentProvider("Function Graph")
			
			jAddr = prog.getAddressFactory().getAddress("0x%X" % node.entryAddress)
			funcObj = listing.getFunctionContaining(jAddr)
			if funcObj != None:
				gotoService.goTo(funcObj.getEntryPoint())
				tool.showComponentProvider(provider,True)
			else:
				tool.showComponentProvider(provider,False)
		else: #except:
			tool.showComponentProvider(provider,False)
			return

	def _hilightCheck(self,evt):
		if self.hilight.isSelected():
			selection = self.tree.getSelectionPath()
			if selection == None:
				return
			node = selection.getLastPathComponent()
			self.highlighter.show(node)
		else:
			self.highlighter.hide()

if __name__ == "__main__":
	frame = TraceFrame()
	frame.show()
