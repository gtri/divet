from java.lang import Enum

# This is a fix to avoid circular imports
# Probably should be moved to a different file
class MemoryColumn(Enum):
	Bank         = 0
	Address      = 1
	Label        = 2
	DataType     = 3
	CurrentValue = 4
	R_W          = 5
	Mutable      = 6
	Tainted      = 7
	StoredValue  = 8
	ReadValues   = 9

	Names = {
		Bank: "Bank",
		Address: "Address",
		Label: "Label",
		DataType: "Data Type",
		CurrentValue: "Current Value",
		R_W : "R/W",
		Mutable: "Mutable",
		Tainted: "Tainted",
		StoredValue: "Stored Value",
		ReadValues: "Read Values",
	}

	@staticmethod
	def count():
		return len(MemoryColumn.Names.keys())
