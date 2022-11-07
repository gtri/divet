		
def break_handle():
	#Bypass printf
	if getReg("pc") == 0x000105DA:
		setReg("pc",0x0000105DE)
		fmt = getString(getReg("r0"))
		print fmt % (getReg("r1"),getReg("r2")),
		return True
	#Do not execute the final return
	else:
		return False
		
resetCpu()
resetMem()
setReg("sp",0xA0000000)
setReg("pc",0x000105AC)
#Set for ThumbMode
setReg("TMode",1)
setReg("ISAModeSwitch",1)
setReg("TB",1)

clrBrk()
print_break = addBrk("BP 000105DA")
done_break  = addBrk("BP 000105F6")
taint_break = addBrk("RW MIN-MAX == * T")
disBrk(taint_break)
argc = getDword(getSym("argc"))
argv = getSym("argv")
for i in xrange(argc):
	p = getDword(argv+i*4)
	b = getByte(p)
	setByte(p,b,True,bankName="ram")
	watchByte(p,bankName="ram")
#startTrace("arm_demo02_thumb.trace")
setCB(break_handle)
run()
