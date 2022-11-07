#!/usr/bin/env jython
import sys
import os

from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import BoxLayout
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JComboBox
from javax.swing import JEditorPane
from java.awt.event import KeyListener
from javax.swing import JScrollPane
from javax.swing import ScrollPaneConstants
from java.awt import Point
from javax.swing import JMenuBar
from javax.swing import JMenu
from javax.swing import JMenuItem
from javax.swing import JCheckBoxMenuItem
from java.awt.event import KeyEvent
from javax.swing import JFileChooser
from java.io import File
from javax.swing import JOptionPane
from javax.swing.table import AbstractTableModel
from javax.swing.table import DefaultTableCellRenderer
from java.awt import Color
from javax.swing import JTable
from javax.swing import JTabbedPane
from javax.swing.event import TableModelEvent


class NumberInputListener(KeyListener):
	def __init__(self,dumpPanel,variableName,intBase=16,callback=None):
		if intBase not in [10,16]:
			raise ValueError,"NumberInputListener inBase must be 10 or 16"
		self.dumpPanel = dumpPanel
		self.variableName = variableName
		self.intBase = intBase
		self.callback = callback
		
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
				if self.callback != None:
					self.callback()

class DifferenceRenderer(DefaultTableCellRenderer):
	def __init__(self,tableModel,*args,**kwargs):
		DefaultTableCellRenderer.__init__(self,*args,**kwargs)
		self.tableModel    = tableModel
		self.compareModels = []
		self.compare       = False

	def setCompare(self,enabled=True):
		self.compare = enabled

	def addCompareModel(self,tableModel):
		if tableModel != self.tableModel:
			self.compareModels.append(tableModel)
		
	def removeCompareModel(self,tableModel):
		try:
			idx = self.compareModels.index(tableModel)
		except ValueError:
			pass
		else:
			del self.compareModels[idx]
		
	def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
		cell = DefaultTableCellRenderer.getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col)
		if self.tableModel.isChanged(row,col):
			cell.setForeground(Color.RED)
		else:
			cell.setForeground(Color.BLACK)
		cell.setBackground(Color.WHITE)
		if self.compare:
			for compareModel in self.compareModels:
				if compareModel.getValueAt(row,col) != value:
					cell.setBackground(Color.YELLOW)
					break
		return cell

class HexTableModel(AbstractTableModel):
	def __init__(self,path,fileOffset=0,bufferSize=2048):
		AbstractTableModel.__init__(self)
		self.byteWidth = 16
		self.bufferSize = bufferSize
		
		self._open(path,fileOffset)
		self._updateBuffer(fileOffset)
		
		self.offsetFmt = "%%0%dX" % len("%X" % self.fileLen)
	
	def _open(self,path,fileOffset):
		self.path = path
		self.fp   = open(path,"rb")
		self.fp.seek(0,2)
		self.fileLen = self.fp.tell()-fileOffset
		self.fp.seek(fileOffset,0)
		self.fileOffset = fileOffset
		
		self.changes = {}
		
	def _updateBuffer(self,offset):
		self.bufferOffset = offset
		self.fp.seek(offset)
		self.buffer = [ord(c) for c in self.fp.read(self.bufferSize)]
	
	def setByteWidth(self,byteWidth):
		self.byteWidth = int(byteWidth)
		if self.byteWidth > self.bufferSize:
			self.bufferSize = self.byteWidth
		self.fireTableStructureChanged()
			
	def setFileOffset(self,fileOffset):
		self.fileOffset = int(fileOffset)
		self.fireTableDataChanged()
				
	def save(self,path=None):
		if path == None:
			path = self.path
		tmpFile = File.createTempFile("tmp","bin")
		tmpPath = tmpFile.getPath()
		outfp = open(tmpPath,"wb")
		self.fp.seek(0)
		while True:
			offset = self.fp.tell()
			cBuffer = self.fp.read(self.bufferSize)
			if not len(cBuffer):
				break
			cBuffer = "".join([chr(self.changes.get(offset+i,ord(cBuffer[i]))) for i in xrange(len(cBuffer))])
			outfp.write(cBuffer)
		outfp.close()
		tmpFile.renameTo(File(path))
		
		self.fp.close()
		self._open(path,self.fileOffset)
		self._updateBuffer(self.bufferOffset)
		self.fireTableDataChanged()
		
	def isChanged(self,row,col):
		byteOffset = self.fileOffset+ (row*self.byteWidth) + (col-1)
		if byteOffset in self.changes:
			return True
		else:
			return False
	
	#######################
	##TableModel Functions
	#######################

	def getRowCount(self):
		if self.fileLen:
			rowCount = self.fileLen / self.byteWidth
			if self.fileLen % self.byteWidth:
				rowCount = rowCount + 1
		else:
			rowCount = 0
		return rowCount
		
	def getColumnCount(self):
		return self.byteWidth+2
		
	def getColumnName(self, col):
		if col == 0:
			return "Offset"
		elif col == self.byteWidth+1:
			return "ASCII"
		else:
			return ("%%0%dX" % len("%X"%(self.byteWidth-1))) % (col-1)
		
	def isCellEditable(self, row, col):
		if col == 0:
			return False
		else:
			return True
	
	def _getByteAt(self,rowOffset,colOffset):
		byteOffset  = rowOffset + colOffset
		if byteOffset in self.changes:
			return self.changes[byteOffset]
		bufferIndex = byteOffset - self.bufferOffset
		if bufferIndex < len(self.buffer):
			return self.buffer[bufferIndex]
		return None
	
	def getValueAt(self, row, col):
		rowOffset = self.fileOffset+(row*self.byteWidth)
		if col == 0:
			return self.offsetFmt % rowOffset
		
		if rowOffset <  self.bufferOffset or \
		   rowOffset >= self.bufferOffset+len(self.buffer):
			self._updateBuffer(rowOffset)

		if col == self.byteWidth+1:
			a = []
			for i in xrange(self.byteWidth):
				b = self._getByteAt(rowOffset,i)
				if b >= 0x20 and b <= 0x7E:
					a.append(chr(b))
				else:
					a.append(".") 
			return "".join(a)
		
		
		b = self._getByteAt(rowOffset,col-1)
		if b == None:
			return "  "
		else:
			return "%02X" % b
					
	def setValueAt(self, value, row, col):
		try:
			b = int(value,16)%0xFF
		except ValueError:
			return
			
		rowOffset = self.fileOffset+(row*self.byteWidth)
		if rowOffset <  self.bufferOffset or \
		   rowOffset >= self.bufferOffset+len(self.buffer):
			self._updateBuffer(rowOffset)
		byteOffset = rowOffset+(col-1)
		bufferIndex = byteOffset - self.bufferOffset
		if bufferIndex < len(self.buffer) and b == self.buffer[bufferIndex]:
			if byteOffset in self.changes:
				del self.changes[byteOffset]
		else:
			self.changes[byteOffset] = b
		self.fireTableCellUpdated(row,self.byteWidth+1)


class HexPanel(JPanel,KeyListener):
	def __init__(self,path):
		self.setLayout( BoxLayout(self, BoxLayout.Y_AXIS) )
		self.byteWidth  = 16
		self.fileOffset = 0

		configPanel = JPanel()
		configPanel.setLayout( BoxLayout(configPanel, BoxLayout.X_AXIS) )
	
		configPanel.add( JLabel("ByteWidth(hex):") )
		byteWidthField =  JTextField("%X" % self.byteWidth, 8)
		byteWidthField.addKeyListener( NumberInputListener(self,"byteWidth",16,self._updateByteWidth) )
		byteWidthField.setMaximumSize( byteWidthField.getPreferredSize() )
		configPanel.add( byteWidthField )
		
		configPanel.add( JLabel("Offset(hex):") )
		offsetField = JTextField("%X" % self.fileOffset, 8)
		offsetField.addKeyListener( NumberInputListener(self,"fileOffset",16,self._updateFileOffset) )
		offsetField.setMaximumSize( offsetField.getPreferredSize() )
		configPanel.add( offsetField )
	
		self.add(configPanel)

		self.hexModel = HexTableModel(path)
		self.hexTable = JTable(self.hexModel)
		self.hexTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
		self.diffRenderer = DifferenceRenderer(self.hexModel)
		self._updateByteWidth()
		self.add( JScrollPane(self.hexTable, ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS, ScrollPaneConstants.HORIZONTAL_SCROLLBAR_ALWAYS)	 )

	def _updateByteWidth(self):
		self.hexModel.setByteWidth(self.byteWidth)
		for i in xrange(self.hexModel.getColumnCount()-2):
	   		self.hexTable.getColumnModel().getColumn(i+1).setCellRenderer(self.diffRenderer)
			self.hexTable.getColumnModel().getColumn(i+1).setPreferredWidth(25);
		self.hexTable.getColumnModel().getColumn(0).setPreferredWidth(100)
		self.hexTable.getColumnModel().getColumn(self.byteWidth+1).setPreferredWidth(215)

	def _updateFileOffset(self):
		self.hexModel.setFileOffset(self.fileOffset)
		self.hexTable.tableChanged(TableModelEvent(self.hexModel))
		
	def setCompare(self,enabled):
		self.diffRenderer.setCompare(enabled)
		self.hexModel.fireTableDataChanged()
		
	def addCompare(self,hexPanel):
		self.diffRenderer.addCompareModel(hexPanel.hexModel)
		self.hexModel.fireTableDataChanged()
		
	def removeCompare(self,hexPanel):
		self.diffRenderer.removeCompareModel(hexPanel.hexModel)
		self.hexModel.fireTableDataChanged()
		
	def save(self,path=None):
		self.hexModel.save(path)
				
class HexEditFrame(JFrame):
	def __init__(self, size=(740, 600)):
		JFrame.__init__(self, "hexEdit", defaultCloseOperation = JFrame.EXIT_ON_CLOSE, size=size)
		
		self.lastDir = None
		self.enableCompare = False
		
		menuBar = JMenuBar()
		self.setJMenuBar(menuBar)
		
		fileMenu = JMenu("File")
		fileMenu.setMnemonic(KeyEvent.VK_F)
		fileMenu.add( JMenuItem("Open",KeyEvent.VK_O,actionPerformed=self._open) )
		fileMenu.add( JMenuItem("Save",KeyEvent.VK_S,actionPerformed=self._save) )
		fileMenu.add( JMenuItem("Save As",KeyEvent.VK_A,actionPerformed=self._saveas) )
		fileMenu.add( JMenuItem("Close",KeyEvent.VK_C,actionPerformed=self._close) )
		fileMenu.addSeparator()
		self.compareCheckbox = JCheckBoxMenuItem("Compare",self.enableCompare,actionPerformed=self._compare)
		fileMenu.add( self.compareCheckbox )
		fileMenu.addSeparator()
		fileMenu.add( JMenuItem("Exit",KeyEvent.VK_X,actionPerformed=self._exit) )
		menuBar.add(fileMenu)
		
		self.setLayout( BoxLayout(self.getContentPane(),BoxLayout.Y_AXIS) )
		self.hexPanels = JTabbedPane(JTabbedPane.TOP)
		self.add(self.hexPanels)
	
	def _open(self,evt=None):
		dlg = JFileChooser()
		if self.lastDir != None:
			dlg.setCurrentDirectory(File(self.lastDir))
		if dlg.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
			path =  dlg.getSelectedFile().getPath()
			self.open(path)
	
	def open(self,path):
		self.lastDir =  os.path.dirname(path)
		name = os.path.basename(path)
		newPanel = HexPanel(path)
		self.hexPanels.add(  name, newPanel )
		
		#Handle multi-file compare
		newPanel.setCompare(self.enableCompare)
		for i in xrange(self.hexPanels.getComponentCount()):
			panel = self.hexPanels.getComponentAt(i)
			panel.addCompare(newPanel)
			newPanel.addCompare(panel)
	
	def _save(self,evt=None):
		self.save()
	
	def save(self):
		self.hexPanels.getSelectedComponent().save()
	
	def _saveas(self,evt=None):
		dlg = JFileChooser()
		if self.lastDir != None:
			dlg.setCurrentDirectory(File(self.lastDir))
		if dlg.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
			path = dlg.getSelectedFile().getPath()
			self.saveas(path)
			
	def saveas(self,path):
		name = os.path.basename(path)
		self.hexPanels.getSelectedComponent().save(path)
		self.hexPanels.setTitleAt(self.hexPanels.getSelectedIndex(),name)
			
	def _close(self,evt=None):
		self.close()
			
	def close(self):
		idx = self.hexPanels.getSelectedIndex()
		oldPanel = self.hexPanels.getComponentAt(idx)
		for i in xrange(self.hexPanels.getComponentCount()):
			panel = self.hexPanels.getComponentAt(i)
			panel.removeCompare(oldPanel)
			oldPanel.removeCompare(panel)
		self.hexPanels.remove(idx)
		
	def _compare(self,evt=None):
		self.compare( not self.enableCompare )

	def compare(self,enable):
		self.enableCompare = enable
		self.compareCheckbox.setSelected(self.enableCompare)
		for i in xrange(self.hexPanels.getComponentCount()):
			self.hexPanels.getComponentAt(i).setCompare(self.enableCompare)

	def _exit(self,evt=None):
		self.setVisible(False)
		self.dispose()

if __name__ == "__main__":	
	def usage():
		print "%s [-h] [-c] [path [path [...] ] ]" % sys.argv[0]
		print ""
		sys.exit(1)
	
	if "-h" in sys.argv:
		usage()
	
	frame = HexEditFrame()
	
	for arg in sys.argv[1:]:
		if arg == "-c":
			frame.compare(True)
		else:
			frame.open(arg)
	
	frame.setVisible(True)
	