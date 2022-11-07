from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing import JCheckBox
from javax.swing import JEditorPane
from javax.swing import JTable
from java.awt.event import KeyListener
from java.awt.event import ActionListener
from javax.swing import JScrollPane
from javax.swing import ScrollPaneConstants
from java.awt import Point
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from java.awt import Color

class NumberInputListener(KeyListener):
	def __init__(self,dumpPanel,variableName,intBase=16):
		if intBase not in [10,16]:
			raise ValueError,"NumberInputListener inBase must be 10 or 16"
		self.dumpPanel = dumpPanel
		self.variableName = variableName
		self.intBase = intBase
		
	def keyTyped(self, event):
		pass
		
	def keyReleased(self,event):
		pass
	
	def keyPressed(self, event):
		keyCode = event.getKeyCode()
		if keyCode == event.VK_ENTER:
			try:
				newValue = abs(int(event.getSource().getText(),self.intBase))
			except ValueError:
				oldValue = getattr(self.dumpPanel,self.variableName,0)
				if intBase == 16:
					event.getSource().setText("%X" % oldValue)
				else:
					event.getSource().setText("%d" % oldValue)
			else:
				setattr(self.dumpPanel,self.variableName,newValue)
				self.dumpPanel.updateMemoryDump(True)

class DisplaySelectionListener(ActionListener):
	def __init__(self,panel):
		self.panel = panel
		
	def actionPerformed(self,evt=None):
		self.panel._displaySelected()

class BankSelectionListener(ActionListener):
	def __init__(self,panel):
		self.panel = panel
		
	def actionPerformed(self,evt=None):
		self.panel.updateMemoryDump(True)

class TableCellRenderer(DefaultTableCellRenderer):
	def __init__(self,panel,*args,**kwargs):
		DefaultTableCellRenderer.__init__(self,*args,**kwargs)
		self.panel = panel
		
	def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
		cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
		bufferIdx = row*self.panel.byteWidth + col-1
		if bufferIdx >= len(self.panel.buffer):
			return cell.setBackground(Color.WHITE)
		else:
			b, p = self.panel.buffer[bufferIdx]
			if p:
				cell.setBackground(Color.YELLOW)
			else:
				cell.setBackground(Color.WHITE)
		return cell

class HexTableModel(AbstractTableModel):
	def __init__(self,panel):
		AbstractTableModel.__init__(self)
		self.panel = panel 

	def getRowCount(self):
		rowCount = self.panel.bufferSize / self.panel.byteWidth
		if self.panel.bufferSize % self.panel.byteWidth:
			rowCount = rowCount + 1
		return rowCount
				
	def getColumnCount(self):
		return self.panel.byteWidth+2
		
	def getColumnName(self, col):
		if col == 0:
			return "Address"
		elif col == self.panel.byteWidth+1:
			return "ASCII"
		else:
			return ("%%0%dX" % len("%X"%(self.panel.byteWidth-1))) % (col-1)
		
	def isCellEditable(self, row, col):
		return False
		
	def getValueAt(self, row, col):
		rowOffset = row*self.panel.byteWidth 
		if col == 0:
			return self.panel.mem.getAddressString(self.panel.offset+rowOffset)

		if col == self.panel.byteWidth+1:
			a = []
			for i in xrange(self.panel.byteWidth):
				bufferIdx = rowOffset+i
				if bufferIdx >= len(self.panel.buffer):
					a.append(" ")
				else:
					b, p = self.panel.buffer[bufferIdx]
					if b >= 0x20 and b <= 0x7E:
						a.append(chr(b))
					else:
						a.append(".") 
			return "".join(a)
		
		bufferIdx = rowOffset+col-1
		if bufferIdx >= len(self.panel.buffer):
			return "  "
			
		b, p = self.panel.buffer[bufferIdx]
		return "%02X" % b


class MemoryDumpPanel(JPanel):
	def __init__(self,endeanEmuMem):
		self.mem = endeanEmuMem
		self.offset = 0
		self.byteWidth = 16
		self.bufferSize = 1024
		self.decay = 5
		self.byteBuffer = []
		
		#Text Formatting stuff
		self.header = "<html><body><tt>"
		self.byteFill = " "
		self.footer = "</tt></body></html>"
		
		configPanel = JPanel()
		configPanel.setLayout( BoxLayout(configPanel, BoxLayout.X_AXIS) )
		
		configPanel.add( JLabel("Display:") )
		self.displayComboBox = JComboBox()
		self.displayComboBox.setEditable(False)
		self.displayComboBox.addItem("Text")
		self.displayComboBox.addItem("Table")
		self.displayComboBox.addActionListener( DisplaySelectionListener(self) )
		configPanel.add( self.displayComboBox )
		
		configPanel.add( JLabel("Bank:") )
		self.bankComboBox = JComboBox()
		self.bankComboBox.setEditable(False)
		self.bankComboBox.addItem("")
		for bankName in self.mem.getBanks():
			self.bankComboBox.addItem(bankName)
		self.bankComboBox.setMaximumSize( self.bankComboBox.getPreferredSize() )
		self.bankComboBox.addActionListener( BankSelectionListener(self) )
		configPanel.add(self.bankComboBox)

		configPanel.add( JLabel("Offset(hex):") )
		offsetField = JTextField("%X" % self.offset, 8)
		offsetField.addKeyListener( NumberInputListener(self,"offset",16) )
		offsetField.setMaximumSize( offsetField.getPreferredSize() )
		configPanel.add( offsetField )
		
		configPanel.add( JLabel("ByteWidth(hex):") )
		byteWidthField =  JTextField("%X" % self.byteWidth, 8)
		byteWidthField.addKeyListener( NumberInputListener(self,"byteWidth",16) )
		byteWidthField.setMaximumSize( byteWidthField.getPreferredSize() )
		configPanel.add( byteWidthField )
		
		configPanel.add( JLabel("BufferSize(dec):") )
		bufferField = JTextField("%d" % self.bufferSize,8)
		bufferField.addKeyListener( NumberInputListener(self,"bufferSize",10) )
		bufferField.setMaximumSize( bufferField.getPreferredSize() )
		configPanel.add( bufferField )

		configPanel.add( JLabel("Decay(dec):") )
		decayField = JTextField("%d" % self.decay,8)
		decayField.addKeyListener( NumberInputListener(self,"decay",10) )
		decayField.setMaximumSize( decayField.getPreferredSize() )
		configPanel.add( decayField )
		
		configPanel.setMaximumSize( configPanel.getPreferredSize() )
				
		self.hexField = JEditorPane()
		self.hexField.setContentType("text/html")
		self.hexField.setEditable(False)
		self.hexFieldPane = JScrollPane(self.hexField)

		self.hexTableModel = HexTableModel(self)
		self.hexTable = JTable(self.hexTableModel)
		self.hexTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
		self.cellRenderer = TableCellRenderer(self)
		self.hexTablePane = JScrollPane(self.hexTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS)
		self.hexTablePane.setVisible(False)
				
		self.setLayout( BoxLayout(self, BoxLayout.Y_AXIS) )
		self.add(configPanel)
		self.add( self.hexFieldPane )

		self.updateMemoryDump(True)

	def _displaySelected(self):
		if self.displayComboBox.getSelectedIndex() == 0:
				if self.hexTablePane.isVisible():
					self.remove(self.hexTablePane)
					self.hexTablePane.setVisible(False)
				if not self.hexFieldPane.isVisible():
					self.hexFieldPane.setVisible(True)
					self.add( self.hexFieldPane )
		elif self.displayComboBox.getSelectedIndex() == 1:
				if self.hexFieldPane.isVisible():
					self.remove(self.hexFieldPane)
					self.hexFieldPane.setVisible(False)
				if not self.hexTablePane.isVisible():
					self.hexTablePane.setVisible(True)
					self.add( self.hexTablePane )
		self.validate()
		self.updateMemoryDump(True)


	def updateMemoryDump(self,reset=False):
		displaySelected = self.displayComboBox.getSelectedIndex()

		bankName = self.bankComboBox.getSelectedItem()
		if not len(bankName):
			bankName = None

		if reset:
			#Reset the buffer
			self.buffer = [[self.mem.getByte(self.offset+i,bankName)[0],0] for i in xrange(self.bufferSize)]
			
			if displaySelected == 0:
				#Generate Header and text format info
				hdrWidth = max(len("%X"%(self.byteWidth-1)),2)
				hdrFmt = "&nbsp;%%0%dX" % hdrWidth
				
				elems = ["<html><body><tt><b>"]
				addrLen = len(self.mem.getAddressString(0))
				elems.append("&nbsp;"*(addrLen+1))
				for i in xrange(self.byteWidth):
					elems.append(hdrFmt % i)
				elems.append("</b>")
				
				self.byteFill = "&nbsp;"*(hdrWidth-2+1)
				self.header = "".join(elems)
				
				pos = Point(0,0)
			
			elif displaySelected == 1:
				self.hexTableModel.fireTableStructureChanged()
				
				self.hexTable.getColumnModel().getColumn(0).setPreferredWidth(150)
				for i in xrange(self.hexTableModel.getColumnCount()-2):
					self.hexTable.getColumnModel().getColumn(i+1).setCellRenderer(self.cellRenderer)
					self.hexTable.getColumnModel().getColumn(i+1).setPreferredWidth(30)
				self.hexTable.getColumnModel().getColumn(self.byteWidth+1).setPreferredWidth(215)
								
		else:
			#Handle the buffer
			for i in xrange(self.bufferSize):
				#Decay
				if self.buffer[i][1]:
					self.buffer[i][1] -= 1
					if displaySelected == 1:
						row = i / self.byteWidth
						col = (i % self.byteWidth) + 1
						self.hexTableModel.fireTableCellUpdated(row,col)
				#Look for new change
				b = self.mem.getByte(self.offset+i,bankName)[0]
				if b != self.buffer[i][0]:
					self.buffer[i] = [b,self.decay]
					if displaySelected == 1:
						row = i / self.byteWidth
						col = (i % self.byteWidth) + 1
						self.hexTableModel.fireTableCellUpdated(row,col)
			
			if displaySelected == 0:
				pos = self.hexField.getParent().getViewPosition()

		if displaySelected == 0:
			self._dumpText()
			self.hexField.updateUI()
			self.hexField.getParent().setViewPosition(pos)

	def _dumpText(self):
		lines = [self.header]
		
		count = 0
		lineASCII = []
		elems = []
		while count < self.bufferSize:
			address = self.offset+count
			if count % self.byteWidth == 0:
				if count:
					#Finish the previous line
					elems.append("&nbsp;&nbsp;")
					elems.append("".join(lineASCII))
					lines.append("".join(elems))
				
				#Start this line
				elems = ["<b>"]
				elems.append(self.mem.getAddressString(address))
				elems.append("</b>&nbsp;")
				lineASCII = []
			elems.append(self.byteFill)
			b,p = self.buffer[count]
			if b >= 0x20 and b <= 0x7E:
				a = chr(b)
			else:
				a = "."

			if p:
				elems.append("<b style=\"background-color:yellow\">%02X</b>" % b)
				lineASCII.append("<b style=\"background-color:yellow\">%s</b>" % a)
			else:
				elems.append("%02X" % b)
				lineASCII.append(a)

			count += 1
		
		#Finish out the last line
		while count % self.byteWidth:
			elems.append(self.byteFill)
			elems.append("&nbsp;&nbsp;")
			lineASCII.append("&nbsp;")
			count += 1
		elems.append("&nbsp;&nbsp;")
		elems.append("".join(lineASCII))
		lines.append("".join(elems))
		
		#Add the foot and send to the JEditorPane
		lines.append(self.footer)
		self.hexField.setText("<br>".join(lines))

		
class MemoryDumpFrame(JFrame):
	def __init__(self, title, endeanEmuMem, size=(800, 600)):
		JFrame.__init__(self, title, size=size)
		
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
		self.panel = MemoryDumpPanel(endeanEmuMem)
		self.add(self.panel)
		
	def updateMemoryDump(self):
		self.panel.updateMemoryDump()
		