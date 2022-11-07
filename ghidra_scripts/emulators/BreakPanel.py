from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JButton
from java.awt import Dimension
from java.lang import Integer
from java.lang import Boolean
from java.lang import String
from javax.swing import BorderFactory
from javax.swing import JScrollPane
from javax.swing.event import TableModelListener
from javax.swing.table import AbstractTableModel
from javax.swing import JTable

class BreakTableModel(AbstractTableModel):	
	def __init__(self, breakConditions):
		AbstractTableModel.__init__(self)
		self.brk = breakConditions
		self.ids = []
		self.colNames = ["Enabled","Triggered","Script","Description"]
		
	
	#######################
	##TableModel Functions
	#######################

	def getRowCount(self):
		return len(self.ids)
		
	def getColumnCount(self):
		return 4
		
	def getColumnName(self, col):
		return self.colNames[col]
	
	def getColumnClass(self, col):
		if col in [0,1]:
			return Boolean
		else:
			return String
	
	def isCellEditable(self, row, col):
		if col in [0,2,3]:
			return True
		else:
			return False
	
	def getValueAt(self, row, col):
		if col == 0:
			if self.ids[row] == None:
				return False
			else:
				return self.brk.isConditionEnabled(self.ids[row])
		elif col == 1:
			if self.ids[row] == None:
				return False
			else:
				return self.brk.isConditionTriggered(self.ids[row])
		elif col == 2:
			if self.ids[row] == None:
				return ""
			else:
				return self.brk.getConditionScript(self.ids[row])
		elif col == 3:
			if self.ids[row] == None:
				return ""
			else:
				descr = self.brk.getConditionDescription(self.ids[row])
				if descr == None:
					return ""
				return str(descr)
		return None
		
	def setValueAt(self, value, row, col):
		if col == 0:
			if self.ids[row] != None:
				self.brk.enableCondition(self.ids[row],value)
		elif col in [2,3]:
			if col == 2:
				script = value
				descr = self.getValueAt(row,3)
			else: #col == 3
				script = self.getValueAt(row,2)
				descr = value
			if self.ids[row] != None:
				self.brk.removeCondition(self.ids[row])
				self.ids[row] = None
			if len(script):
				self.ids[row] = self.brk.addScriptCondition(script,descr)
				self.fireTableDataChanged()
			
	
	#######################
	##Additional Functions
	#######################
	
	def addRow(self):
		self.ids.append(None)
	
	def removeRows(self, rows):
		newIds = []
		for r in xrange(len(self.ids)):
			if r in rows:
				if self.ids[r] != None:
					self.brk.removeCondition(self.ids[r])
			else:
				newIds.append(self.ids[r])
		self.ids = newIds
		
	def updateIds(self):
		newIds = []
		condIds = self.brk.getConditionIds()
		for id in self.ids:
			if id != None and id in condIds:
				newIds.append(id)
		for id in condIds:
			if id not in self.ids:
				newIds.append(id)
		self.ids = newIds
		
	def saveFile(self,fp):
		fp.write("[Break]\n")
		for id in self.ids:
			if id != None:
				enabled  = self.brk.isConditionEnabled(id)
				script = self.brk.getConditionScript(id)
				descr = self.brk.getConditionDescription(id)
				if enabled:
					fp.write("E:%s:%s\n" % (script,descr))
				else:
					fp.write("D:%s:%s\n" % (script,descr))
		fp.write("\n")
		
	def loadFile(self,fp):
		#Clear out existing conditions and associated UI elements
		self.brk.clear()
		self.ids = []
		
		#Parse the file
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
				if line.strip().lower() == "[break]":
					ready = True
				elif ready:
					break #Finished read section
				else:
					ready = False
				
			if ready:
				print "Ready"
				items = line.split(":")
				if len(items) >= 2:
					enabledString = items[0].strip().lower()
					if enabledString == "e":
						enabled = True
					elif enabledString == "d":
						enabled = False
					else:
						continue
					script = items[1].strip()
					descr = ":".join(items[2:]).strip()
					print repr(script),repr(descr)
					try:
						id = self.brk.addScriptCondition(script,descr)
					except ValueError:
						continue
					self.brk.enableCondition(id,enabled)
					self.ids.append(id)

class BreakModelListener(TableModelListener):
	def __init__(self,table):
		self.table = table
	
	def tableChanged(self,event):
		self.table.updateUI()
		
class BreakPanel(JPanel):
	def __init__(self,breakConditions):
		self.brk = breakConditions
		self.setBorder(BorderFactory.createTitledBorder("Break Conditions"))
		self.setLayout( BoxLayout(self,BoxLayout.Y_AXIS) )
		buttonPanel = JPanel()
		buttonPanel.setLayout( BoxLayout(buttonPanel,BoxLayout.X_AXIS) )
		buttonPanel.add( JButton("Add", actionPerformed=self._addCond) )
		buttonPanel.add( JButton("Remove", actionPerformed=self._rmCond) )
		self.add(buttonPanel)
		
		self.breakModel = BreakTableModel(breakConditions)
		self.breakTable = JTable(self.breakModel)
		self.breakModel.addTableModelListener( BreakModelListener(self.breakTable) )
		self.breakTable.getColumnModel().getColumn(0).setPreferredWidth(65);
		self.breakTable.getColumnModel().getColumn(1).setPreferredWidth(70);
		self.breakTable.getColumnModel().getColumn(2).setPreferredWidth(175);
		self.breakTable.getColumnModel().getColumn(3).setPreferredWidth(250);
		self.breakTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
		self.add(JScrollPane(self.breakTable))
		
		self.condPanel = JPanel()
		self.condPanel.setLayout( BoxLayout(self.condPanel,BoxLayout.Y_AXIS) )
		self.add( JScrollPane(self.condPanel) )
		
	def _addCond(self,evt):
		self.breakModel.addRow()
		self.breakTable.updateUI()
		
	def _rmCond(self,evt):
		rows = self.breakTable.getSelectedRows()
		self.breakModel.removeRows(rows)
		self.breakTable.updateUI()
					
	def updateBreakConditions(self):
		self.breakModel.updateIds()
		self.breakTable.updateUI()
			
	def saveFile(self,fp):
		self.breakModel.saveFile(fp)
		
	def loadFile(self,fp):
		self.breakModel.loadFile(fp)
		self.updateBreakConditions()
		