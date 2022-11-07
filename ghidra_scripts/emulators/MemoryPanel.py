from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JButton
from javax.swing import JTextField
from javax.swing import JComboBox
from java.awt import Dimension
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from java.awt import Color
from javax.swing import JTable
from javax.swing import JScrollPane
from javax.swing import JTabbedPane
from javax.swing import JTextArea
from java.lang import String
from java.lang import Boolean
from java.lang import Integer
from javax.swing import BorderFactory
from javax.swing import JCheckBox
from java.awt.event import KeyListener
from java.awt.event import WindowListener

from EmulatedMemory import AREAD,AWRITE
from Enums import MemoryColumn
from TableDataViewMouseListener import TableDataViewMouseListener
from MemoryDumpPanel import MemoryDumpFrame


class MemoryChangedCellRenderer(DefaultTableCellRenderer):
	def __init__(self,tableModel,*args,**kwargs):
		DefaultTableCellRenderer.__init__(self,*args,**kwargs)
		self.tableModel = tableModel

	def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
		cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
		bankName, address, byteWidth = self.tableModel.rows[row]
		access = self.tableModel.accessStates.get((bankName,address), 0)
		if access & AWRITE:
			if isSelected:
				cell.setBackground(Color.GREEN)
			else:
				cell.setBackground(Color.YELLOW)
		elif isSelected:
			cell.setBackground(Color.BLUE)
		else:
			cell.setBackground(None)
		return cell

class MemoryTableModel(AbstractTableModel):
	def __init__(self, emuMem):
		AbstractTableModel.__init__(self)
		self.emuMem = emuMem
		self.addressFormat = self.emuMem.addressFormat

		self.rows = []
		self.accessStates = {}
	
	#######################
	##TableModel Functions
	#######################

	def getRowCount(self):
		return len(self.rows)
		
	def getColumnCount(self):
		return MemoryColumn.count()
		
	def getColumnName(self, col):
		return MemoryColumn.Names[col]
	
	def getColumnClass(self, col):
		if col in [MemoryColumn.Mutable, MemoryColumn.Tainted]:
			return Boolean
		else:
			return String
	
	def isCellEditable(self, row, col):
		return col in [MemoryColumn.Mutable,
					   MemoryColumn.Tainted,
					   MemoryColumn.ReadValues]
	
	def getValueAt(self, row, col):
		bankName, address, byteWidth = self.rows[row]
		self.emuMem.setByteWidth(byteWidth)
		if col == MemoryColumn.Bank:
			return bankName
		elif col == MemoryColumn.Address:
			return self.emuMem.getAddressString(address)
		elif col == MemoryColumn.Label:
			return self.emuMem.getSymbolName(address)
		elif col == MemoryColumn.DataType:
			dataType = self.emuMem.getDataType(address)
			if dataType != "?":
				return dataType.getDisplayName()
			else:
				return dataType
		elif col == MemoryColumn.CurrentValue:
			return self.emuMem.getCurrentValueString(address,bankName)
		elif col == MemoryColumn.R_W:
			access = self.accessStates.get((bankName,address), 0)
			if access == AREAD|AWRITE:
				return "RW"
			elif access == AREAD:
				return "R"
			elif access == AWRITE:
				return "W"
			else:
				return ""
		elif col == MemoryColumn.Mutable:
			return self.emuMem.isMutable(address,bankName)
		elif col == MemoryColumn.Tainted:
			return self.emuMem.isTainted(address,bankName)
		elif col == MemoryColumn.StoredValue:
			return self.emuMem.getStoredValueString(address,bankName)
		elif col == MemoryColumn.ReadValues:
			return self.emuMem.getReadValuesString(address,bankName)
		else:
			return None
			
	def setValueAt(self, value, row, col):
		bankName, address, byteWidth = self.rows[row]
		self.emuMem.setByteWidth(byteWidth)
		if col == MemoryColumn.Mutable:
			self.emuMem.setMutable(address, value, bankName)
		elif col == MemoryColumn.Tainted:
			self.emuMem.setTaint(address, value, bankName)
		elif col == MemoryColumn.ReadValues:
			read_values = []
			value = value.strip()
			if not len(value):
				self.emuMem.setReadValues(address, read_values, bankName)
			else:
				error = False
				items = value.split(",")
				for item in items:
					item = item.strip()
					if not len(item):
						error = True
					if item[0] == item[-1] and item[0] in ["\'", "\""]:
						read_values = read_values + [ord(c) for c in item[1:-1]]
					else:
						try:
							read_values.append(int(item, 16))
						except ValueError:
							error = True
				if not error:
					self.emuMem.setReadValues(address, read_values, bankName)

	########################
	# Additional Functions #
	########################
	
	def addRows(self, bankName, addresses, byteWidth=None):
		if bankName == None:
			bankName = self.emuMem.getBanks()[0]
		elif bankName not in self.emuMem.getBanks():
			return
		for idx in xrange(len(addresses)):
			if byteWidth == None:
				newAddress, newByteWidth = addresses[idx]
			else:
				newByteWidth = byteWidth
				newAddress = addresses[idx]
				
			if type(newAddress) in [int, long] and newAddress >= 0:
				append = True
				for i in xrange(len(self.rows)):
					rowBank, rowAddress, rowByteWidth = self.rows[i]
					if rowAddress == newAddress:
						if rowBank == bankName and rowByteWidth == newByteWidth:
							# This address/byteWidth is already being watched
							append = False
							break
						elif rowByteWidth > newByteWidth:
							# Add a row for this watch
							self.rows.insert( i, (bankName,newAddress,newByteWidth) )
							append = False
							break
					elif rowAddress > newAddress:
						# Add a row for this watch
						self.rows.insert( i, (bankName,newAddress,newByteWidth) )
						append = False
						break
				if append:
					self.rows.append( (bankName,newAddress,newByteWidth) )

	def removeRows(self, rows):
		self.rows = [self.rows[i] for i in xrange(len(self.rows)) if i not in rows]
	
	def removeAllRows(self):
		self.rows = []
	
	def setAccessStates(self,accessStates):
		self.accessStates = accessStates
	
	def saveFile(self, fp):
		fp.write("[Memory]\n")
		fp.write("default: %02X\n" % self.emuMem.getDefaultValue())
		for bankName, address, byteWidth in self.rows:
			saddr = self.emuMem.getAddressString(address)
			fp.write("%s: %s, %d, " % (bankName,saddr,byteWidth))
			if not self.emuMem.isMutable(address):
				fp.write("c, ")
			if self.emuMem.isManuallyTainted(address):
				fp.write("t, ")
			fp.write(self.emuMem.getReadValuesString(address))
			fp.write("\n")
		fp.write("\n")
		
	def loadFile(self, fp):
		self.emuMem.clear()
		self.rows = []
		fp.seek(0)
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
				if line.strip().lower() == "[memory]":
					ready = True
				elif ready:
					break #Finished read section
				else:
					ready = False
				
			if ready:
				items = line.split(":")
				if len(items) == 2:
					if items[0].strip().lower() == "default":
						try:
							value = int(items[1].strip(),16)
							self.emuMem.setDefaultValue(value)
						except ValueError:
							print "Unable to set default memory value"
							continue
					else:
						bankName = items[0].strip()
						values = [x.strip().lower() for x in items[1].split(",")]
						if len(values) < 2:
							print "Unable to parse memory line %s" % repr(line.strip())
							continue
						saddr = values[0].strip()
						try:
							addr = int(saddr, 16)
						except ValueError:
							print "Unable to parse address: %s" % repr(saddr)
							continue
						if values[1] == "*": #Memory dump, treat line as a "bag of bytes"
							values = values[2:]
							mutable = True
							tainted = False
							self.emuMem.setByteWidth(1)
							baseAddr = addr
							for value in values:
								if not len(value):
									continue
								elif value == "c":
									mutable = False
								elif value == "t":
									tainted = True
								else:
									value = value.replace(" ","")
									if len(value)%2:
										continue
									addr = baseAddr
									self.addRows(bankName,range(addr,addr+(len(value)/2)),1)
									for i in xrange(len(value)/2):
										try:
											byte = int(value[(i*2):(i*2)+2],16)
										except ValueError:
											continue
										self.emuMem.setMutable(addr,mutable)
										self.emuMem.setTaint(addr,tainted)
										read_values = self.emuMem.getReadValues(addr)
										read_values.append(byte)
										self.emuMem.setReadValues(addr,read_values)
										addr = addr + 1
						else: #Treat line as a list of interger values
							try:
								byteWidth = int(values[1])
							except ValueError:
								print "Unable to parse byte width: %s" % repr(byteWidth)
								continue
							values = values[2:]
							self.addRows(bankName, [addr], byteWidth)
							self.emuMem.setByteWidth(byteWidth)
							self.emuMem.setMutable(addr, True)
							self.emuMem.setTaint(addr, False)
							read_values = []
							for value in values:
								if not len(value):
									continue
								elif value == "c":
									self.emuMem.setMutable(addr, False)
								elif value == "t":
									self.emuMem.setTaint(addr, True)
								else:
									try:
										read_values.append(int(value, 16))
									except ValueError:
										continue
							self.emuMem.setReadValues(addr, read_values)

class AddrKeyListener(KeyListener):
	def __init__(self, panel):
		self.panel = panel
	
	def keyTyped(self, event):
		pass
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		keyCode = event.getKeyCode()
		if keyCode == event.VK_ENTER:
			self.panel.addAddresses(event)

class TableKeyListener(KeyListener):
	def __init__(self, panel):
		self.panel = panel
	
	def keyTyped(self, event):
		pass
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		keyCode = event.getKeyCode()
		if keyCode == event.VK_DELETE:
			self.panel.removeAddresses(event)


class HexDumpFrameListener(WindowListener):
	def __init__(self,memPanel):
		self.memPanel = memPanel
	def windowActivated(self,evt):
		pass
	def windowClosed(self,evt):
		pass
	def windowClosing(self,evt):
		i = 0
		while i < len(self.memPanel.hexDumps):
			if self.memPanel.hexDumps[i] == evt.getSource():
				self.memPanel.hexDumps[i] = None
				break
			i+=1
	def windowDeactivated(self,evt):
		pass
	def windowDeiconified(self,evt):
		pass
	def windowIconified(self,evt):
		pass
	def windowOpened(self,evt):
		pass

class MemoryPanel(JPanel):
	def __init__(self, emuMem, ghidraProgram=None):
		JPanel.__init__(self)
		
		self.emuMem = emuMem
		self.ghidraProgram = ghidraProgram
		self.memModel = MemoryTableModel(self.emuMem)
		self.hexDumps = []
		
		self.setBorder(BorderFactory.createTitledBorder("Watch Memory"))
		self.setLayout( BoxLayout(self, BoxLayout.Y_AXIS) )
		
		self.addr_panel = JPanel()
		self.addr_panel.setLayout( BoxLayout(self.addr_panel, BoxLayout.X_AXIS) )
		self.addrField = JTextField()
		self.addrField.setMaximumSize( Dimension(Integer.MAX_VALUE, self.addrField.getPreferredSize().height) )
		self.addrField.addKeyListener(AddrKeyListener(self))
		self.addr_panel.add( self.addrField )
		
		self.byteWidthComboBox = JComboBox()
		self.byteWidthComboBox.setEditable(False)
		self.byteWidthComboBox.addItem("byte")
		self.byteWidthComboBox.addItem("word")
		self.byteWidthComboBox.addItem("dword")
		self.byteWidthComboBox.addItem("qword")
		self.byteWidthComboBox.setMaximumSize( self.byteWidthComboBox.getPreferredSize() )
		self.addr_panel.add(self.byteWidthComboBox)
		
		self.bankNames = emuMem.getBanks()
		self.bankCombo = JComboBox(self.bankNames)
		self.bankCombo.setEditable(False)
		self.bankCombo.setMaximumSize( self.bankCombo.getPreferredSize() )
		self.addr_panel.add(self.bankCombo)
		
		self.addr_panel.add( JButton("Add", actionPerformed=self.addAddresses) )
		self.addr_panel.add( JButton("Remove", actionPerformed=self.removeAddresses) ) 
		self.add( self.addr_panel )

		self.watchon_panel = JPanel()
		self.watchon_panel.setLayout( BoxLayout(self.watchon_panel, BoxLayout.X_AXIS) )
		self.watchOnWrite = JCheckBox("Watch on write", False)
		self.watchon_panel.add( self.watchOnWrite )
		self.watchOnTaintedWrite = JCheckBox("Watch on tainted write", True)
		self.watchon_panel.add( self.watchOnTaintedWrite )
		self.watchOnRead = JCheckBox("Watch on read", False)
		self.watchon_panel.add( self.watchOnRead )
		self.watchon_panel.add( JButton("HexDump", actionPerformed=self.openDump) )
		self.add( self.watchon_panel )
		
		self.edit_panel = JPanel()
		self.edit_panel.setLayout( BoxLayout(self.edit_panel, BoxLayout.X_AXIS) )
		self.edit_panel.add( JLabel("Default Read:") )
		self.defaultField = JTextField()
		self.defaultField.setMaximumSize( Dimension(Integer.MAX_VALUE, self.defaultField.getPreferredSize().height) )
		self.edit_panel.add( self.defaultField )
		self.edit_panel.add( JButton("Update Default", actionPerformed=self.updateDefault) )
		self.edit_panel.add( JButton("Toggle Mutable", actionPerformed=self.toggleMutable) )
		self.edit_panel.add( JButton("Reset", actionPerformed=self.resetMemory) )
		self.add( self.edit_panel )
		
		self.memTable = JTable(self.memModel)
		self.memTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
		self.memTable.addMouseListener(TableDataViewMouseListener(self.emuMem, self.memTable))
		self.memTable.addKeyListener(TableKeyListener(self))
		changedRenderer = MemoryChangedCellRenderer(self.memModel)
		for col in xrange(MemoryColumn.R_W+1):
			self.memTable.getColumnModel().getColumn(col).setCellRenderer(changedRenderer)
		self.memTable.getColumnModel().getColumn(MemoryColumn.StoredValue).setCellRenderer(changedRenderer)
		
		self.stepRecordArea = JTextArea()
		self.stepRecordArea.setEditable(False)
		
		tabbedPane = JTabbedPane()
		tabbedPane.addTab("Memory",JScrollPane(self.memTable))
		tabbedPane.addTab("Access",JScrollPane(self.stepRecordArea))
		self.add(tabbedPane)
	
	def reviewStep(self):
		accessStates = {}
		newAddresses = {}
		self.stepRecordArea.setText("")
		stepRecord = self.emuMem.getStepRecord()
		for accessRecord in stepRecord:
			bankName, accessType, address, value, tainted = accessRecord[:5]
			byteWidth = accessRecord[-1]
			self.emuMem.setByteWidth(byteWidth)
			accessStr = self.emuMem.getRecordString(accessRecord)
			self.stepRecordArea.append(accessStr)
			
			#Append (or) this access to the internally tracked access
			currentAccess = accessStates.get((bankName,address),0)
			accessStates[(bankName,address)] = currentAccess | accessType
			
			#Check to see if accesed addresses needs to be watched
			if accessType == AREAD:
				if self.watchOnRead.isSelected():
					if not newAddresses.has_key(bankName):
						newAddresses[bankName] = []
					newAddresses[bankName].append((address,byteWidth))
			elif accessType == AWRITE:
				if self.watchOnTaintedWrite.isSelected() and tainted:
					if not newAddresses.has_key(bankName):
						newAddresses[bankName] = []
					newAddresses[bankName].append((address,byteWidth))
				elif self.watchOnWrite.isSelected():
					if not newAddresses.has_key(bankName):
						newAddresses[bankName] = []
					newAddresses[bankName].append((address,byteWidth))
						
		#Commit changes to the model
		self.memModel.setAccessStates(accessStates)
		for bankName in newAddresses:
			self.memModel.addRows(bankName,newAddresses[bankName])

	def updateMemory(self):
		self.reviewStep()
		self._refreshBanks()
		self.memTable.updateUI()
		
		#Handle any open dumps
		for hexDump in self.hexDumps:
			if hexDump != None:
				hexDump.updateMemoryDump()

	def _refreshBanks(self):
		bankNames = self.emuMem.getBanks()
		if bankNames != self.bankNames:
			self.bankNames = bankNames
			self.bankCombo.removeAllItems()
			for bankName in bankNames:
				self.bankCombo.addItem(bankName)

	def _getAddrInt(self,addr):
		intAddr = None
		addr = addr.strip()
		try:
			intAddr = int(addr,16)
		except ValueError:
			if self.ghidraProgram != None:
				symbol = self.ghidraProgram.getSymbolTable().getSymbol(addr)
				if symbol != None:
					intAddr = symbol.getAddress().getOffset()
		if intAddr == None:
			raise ValueError,"Address %s is invalid." % repr(addr)
		return intAddr
		
	def addAddresses(self, e):
		s = self.addrField.getText().strip()
		bankName = self.bankCombo.getSelectedItem()
		if s != "":
			byteWidth = [1,2,4,8][self.byteWidthComboBox.getSelectedIndex()]
			if "-" in s:
				items = s.split("-")
				if len(items) != 2:
					error = True
				else:
					try:
						start, end = [self._getAddrInt(x) for x in items]
					except ValueError:
						raise ValueError, "Invalid address range to add"
					else:
						self.memModel.addRows(bankName,range(start, end + 1,byteWidth),byteWidth)
			else:
				try:
					addrs = [self._getAddrInt(x) for x in s.split(",")]
				except ValueError:
					raise ValueError, "Invalid address to add"
				else:
					self.memModel.addRows(bankName,addrs,byteWidth)
			self.memTable.updateUI()
			
	def removeAddresses(self, e):
		self.memModel.removeRows(self.memTable.getSelectedRows())
		self.memTable.clearSelection()
		self.memTable.updateUI()
		
	def updateDefault(self, e):
		value = int(self.defaultField.getText(), 16)
		self.emuMem.setDefaultValue(value)
		self.memTable.updateUI()
		
	def toggleMutable(self, e):
		for row in self.memTable.getSelectedRows():
			value = self.memModel.getValueAt(row, MemoryColumn.Mutable)
			self.memModel.setValueAt( not value, row, MemoryColumn.Mutable)
		self.memTable.updateUI()

	def resetMemory(self, e):
		self.emuMem.reset()
		self.memTable.updateUI()
	
	def openDump(self,e):
		title = "Memory (Hex) Dump [%d]" % len(self.hexDumps)
		hexDumpFrame = MemoryDumpFrame(title,self.emuMem)
		hexDumpFrame.addWindowListener(HexDumpFrameListener(self))
		hexDumpFrame.setVisible(True)
		self.hexDumps.append(hexDumpFrame)
	
	def saveFile(self, fp):
		return self.memModel.saveFile(fp)
		
	def loadFile(self, fp):
		return self.memModel.loadFile(fp)
