		
def break_handle():
	#Bypass printf
	if getReg("pc") == 0x00010674:
		setReg("pc",0x00010678)
		fmt = getString(getReg("r0"))
		print fmt % (getReg("r1"),getReg("r2")),
		return True
	#Do not execute the final return
	else:
		return False
		
resetCpu()
resetMem()
setReg("sp",0xA0000000)
setReg("pc",0x0001062c)
clrBrk()
print_break = addBrk("BP 00010674")
done_break  = addBrk("BP 000106a4")
taint_break = addBrk("RW MIN-MAX == * T")
disBrk(taint_break)
argc = getDword(getSym("argc"))
argv = getSym("argv")
for i in xrange(argc):
	p = getDword(argv+i*4)
	b = getByte(p)
	setByte(p,b,True,bankName="ram")
	watchByte(p,bankName="ram")
#startTrace("arm_demo02.trace")
setCB(break_handle)
run()
