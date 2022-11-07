# Apply zx81 Symbols
#@author Daniel Tabor
#@category Symbol
#@keybinding
#@menupath
#@toolbar


path = askFile("Please specify zx81 symbol file to apply","Apply")
fp = open(str(path),"rb")

while True:
	line = fp.readline()
	if not len(line):
		break
	address, name = line.split(" ")
	address = int(address.strip(),16)
	name = str(name.strip())
	jAddr = getAddressFactory().getAddress(hex(address))
	symbol = getSymbolAt(jAddr)
	print "0x%08X => %s" % (address,name)
	if symbol:
		symbol.setName(name,symbol.getSource())
	else:
		createLabel(jAddr,name,True)
