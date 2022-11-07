def break_handle():
	global stack_reg
	#Bypass printf
	if getReg("pc") == 0x80000534:
		fmt =  getString(getDword(getReg(stack_reg)))
		print fmt % (getDword(getReg(stack_reg)+4),getDword(getReg(stack_reg)+8)),
		setReg("pc",0x8000053a)
		return True
	#Do not execute the final return
	else:
		return False
		
resetCpu()
resetMem()
if "ram" in api.mem.getBanks():
	#archpcode
	setBank("ram")
	stack_reg = "sp"
else:
	#arch6502
	setBank("MEM")
	stack_reg = "a7"
	
setReg("pc",0x800004f0)
setReg(stack_reg,0xA0000000)
clrBrk()
print_break = addBrk("BP 80000534","printf",break_handle)
done_break  = addBrk("BP 80000552","return")
#startTrace("/home/dtabor/pcode.trace")
run()
