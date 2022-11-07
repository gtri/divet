from java.awt import Dimension
from java.awt.event import MouseAdapter
from javax.swing import JFrame
from javax.swing import JTable
from javax.swing import JScrollPane

from ghidra.program.model.data import DataType
from ghidra.program.model.listing import Data
from ghidra.program.database.data import StructureDB

from java.lang import Enum
from javax.swing.table import AbstractTableModel

from Enums import MemoryColumn

class TableDataViewMouseListener(MouseAdapter):
	def __init__(self, emuMem, memTable):
		self.emuMem = emuMem
		self.memTable = memTable
	
	def mouseClicked(self, mouseEvent):
		if mouseEvent.getClickCount() == 2:
			# Double click
			row = mouseEvent.getSource().getSelectedRow()
			col = mouseEvent.getSource().getSelectedColumn()
			if col in [MemoryColumn.DataType, MemoryColumn.CurrentValue]:
				addr = int(self.memTable.getValueAt(row, MemoryColumn.Address), 16)
				dataType = self.emuMem.getDataType(addr)
				if type(dataType) is StructureDB:
					if col == MemoryColumn.DataType:
						# Create a table showing the structure format
						self.createJFrameDataType(dataType=dataType)
					else:
						# Create a table showing the structure format + this variable's data
						name = self.memTable.getValueAt(row, MemoryColumn.Label)
						self.createJFrameDataType(name, addr)
	
	def createJFrameDataType(self, name=None, addr=None, dataType=None):
		data = dataType if dataType is not None else self.emuMem.getData(addr)
		tableModel = DataStructTable(data, addr, self.emuMem, self.memTable)
		numRows = tableModel.getRowCount()
		numCols = tableModel.getColumnCount()
		table = JTable(tableModel)
		cols = table.getColumnModel()
		
		for i in range(0, numCols):
			cols.getColumn(i).setPreferredWidth(tableModel.TableNames.DefaultWidths[i])
		maxWidth = sum([tableModel.TableNames.DefaultWidths[i] for i in range(0, numCols)])
		table.setRowHeight(25)
		maxHeight = 25 * (numRows + 1) + 3
		
		scroll = JScrollPane(table)
		scroll.setPreferredSize(Dimension(maxWidth, maxHeight))
		if name is None:
			name = data.getName() + " (struct view)"
		else:
			name += " (data view)"
		frame = JFrame(name)
		frame.add(scroll)
		frame.setPreferredSize(Dimension(maxWidth, maxHeight + 40))
		frame.pack()
		frame.show()

class DataStructTable(AbstractTableModel):
	class TableNames(Enum):
		Index = 0
		Name = 1
		Type = 2
		Size = 3
		Value = 4
		
		Names = {
			Index:	"Index",
			Name:	"Name",
			Type:	"Type",
			Size:	"Size",
			Value:	"Value"
		}

		DefaultWidths = {
			Index:	50,
			Name:	150,
			Type:	100,
			Size:	50,
			Value:	150
		}				
		
		@staticmethod
		def count():
			return len(TableNames.Names.keys())

	def __init__(self, data, addr, emuMem=None, memTable=None):
		AbstractTableModel.__init__(self)
		self.numRows = data.getNumComponents()
		self.numCols = 4
		if isinstance(data, Data):
			self.numCols += 1
		
		self._data = []
		self.offsets = []
		self.addr = addr
		self.data = data
		self.emuMem = emuMem
		self.memTable = memTable
		
		currentOffset = 0
		for i in range(self.numRows):
			component = data.getComponent(i)
			name = component.getFieldName()
			dataType = component.getDataType()
			self.offsets.append(currentOffset)
			currentOffset += component.getLength()
			self._data.append([i, name, dataType.getName(), dataType.getLength()])
				
	def getRowCount(self):
		return self.numRows
	
	def getColumnCount(self):
		return self.numCols
	
	def getColumnName(self, col):
		return self.TableNames.Names[col]
	
	def getValueAt(self, row, col):
		if col == self.TableNames.Value:
			self.emuMem.setByteWidth(self._data[row][self.TableNames.Size])
			_, _, _, value, _ = self.emuMem._read(self.addr + self.offsets[row])
			return "0x%X" % value
		return self._data[row][col]
	
	def setValueAt(self, value, row, col):
		if col == self.TableNames.Value:
			self.emuMem.setByteWidth(self._data[row][self.TableNames.Size])
			_, _, _, _, tainted = self.emuMem._read(self.addr + self.offsets[row])
			self.emuMem._write(self.addr + self.offsets[row], int(value, 16), tainted)
		else:
			self._data[row][col] = value
	
	def isCellEditable(self, row, col):
		return True if col == self.TableNames.Value else False