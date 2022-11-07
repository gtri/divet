		
def break_handle():
	#Bypass printf
	if getReg("eip") == 0x08049e37:
		setReg("eip",0x08049e3c)
		return True
	#Do not execute the final return
	else:
		return False
		
resetCpu()
resetMem()
setReg("esp",0xA0000000)
setReg("eip",0x08049DDB)
clrBrk()
print_break = addBrk("BP 08049e37")
done_break  = addBrk("BP 08049e5b")
setCB(break_handle)
run()
