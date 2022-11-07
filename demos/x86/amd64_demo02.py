		
def break_handle():
	#Bypass printf
	if getReg("rip") == 0x00401df3:
		setReg("rip",0x00401df8)
		return True
	#Do not execute the final return
	else:
		return False
		
resetCpu()
resetMem()
setReg("rsp",0xA0000000)
setReg("rip",0x00401d98)
clrBrk()
print_break = addBrk("BP 00401df3")
done_break  = addBrk("BP 00401e0d")
setCB(break_handle)
run()
