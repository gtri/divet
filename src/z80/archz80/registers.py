import struct
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__),"z80core.jar"))

from z80core import Z80

def im2i(im):
	if im == Z80.IntMode.IM0:
		return 0
	elif im == Z80.IntMode.IM1:
		return 1
	elif im == Z80.IntMode.IM2:
		return 2
	raise ValueError,"IntMode is invalid"

def i2im(i):
	if i == 0:
		return Z80.IntMode.IM0
	elif i == 1:
		return Z80.IntMode.IM1
	elif i == 2:
		return Z80.IntMode.IM2
	raise ValueError,"IntMode is invalid"
	

class Registers():
	flagMasks = {
		"C":Z80.CARRY_MASK,
		"N":Z80.ADDSUB_MASK,
		"PV":Z80.PARITY_MASK,
		"H":Z80.HALFCARRY_MASK,
		"Z":Z80.ZERO_MASK,
		"S":Z80.SIGN_MASK
	}
	
	def __init__(self):
		self.cpu = None
		
	def setCpu(self,cpu):
		self.cpu = cpu
		
	def reset(self):
		self.cpu.reset()
	
	def getRegister(self,name):
		if name in ["fS_","fZ_","fH_","fPV_","fN_","fC_"]:
			if self.cpu.getRegFx()&self.flagMasks[name[1:-1]]:
				value = True
			else:
				value = False
			return value,False
		elif name == "fS":
			return int(self.cpu.isSignFlag()),False
		elif name == "fZ":
			return int(self.cpu.isZeroFlag()),False
		elif name == "fH":
			return int(self.cpu.isHalfCarryFlag()),False
		elif name == "fPV":
			return int(self.cpu.isParOverFlag()),False
		elif name == "fN":
			return int(self.cpu.isAddSubFlag()),False
		elif name == "fC":
			return int(self.cpu.isCarryFlag()),False
		elif name == "A":
			return self.cpu.getRegA(),False
		elif name == "B":
			return self.cpu.getRegB(),False
		elif name == "C":
			return self.cpu.getRegC(),False
		elif name == "D":
			return self.cpu.getRegD(),False
		elif name == "E":
			return self.cpu.getRegE(),False
		elif name == "H":
			return self.cpu.getRegH(),False
		elif name == "L":
			return self.cpu.getRegL(),False
		elif name == "PC":
			return self.cpu.getRegPC(),False
		elif name == "SP":
			return self.cpu.getRegSP(),False
		elif name == "IX":
			return self.cpu.getRegIX(),False
		elif name == "IY":
			return self.cpu.getRegIY(),False
		elif name == "I":
			return self.cpu.getRegI(),False
		elif name == "R":
			return self.cpu.getRegR(),False
		elif name == "HALT":
			return int(self.cpu.isHalted()),False
		elif name == "IFF1":
			return int(self.cpu.isIFF1()),False
		elif name == "IFF2":
			return int(self.cpu.isIFF2()),False
		elif name == "IM":
			return im2i(self.cpu.getIM()),False
		elif name == "A_":
			return self.cpu.getRegAx(),False
		elif name == "B_":
			return self.cpu.getRegBx(),False
		elif name == "C_":
			return self.cpu.getRegCx(),False
		elif name == "D_":
			return self.cpu.getRegDx(),False
		elif name == "E_":
			return self.cpu.getRegEx(),False
		elif name == "H_":
			return self.cpu.getRegHx(),False
		elif name == "L_":
			return self.cpu.getRegLx(),False
		else:
			return 0,False
		
	def setRegister(self,name,value,taint):
		if name in ["fS_","fZ_","fH_","fPV_","fN_","fC_"]:
			flags = getRegFx()
			if value:
				flags = flags | self.flagMasks[name[1:-1]]
			else:
				flags = flags & ~self.flagMasks[name[1:-1]]
		elif name == "fS":
			self.cpu.setSignFlag(bool(value))
		elif name == "fZ":
			self.cpu.setZeroFlag(bool(value))
		elif name == "fH":
			self.cpu.setHalfCarryFlag(bool(value))
		elif name == "fPV":
			self.cpu.setParOverFlag(bool(value))
		elif name == "fN":
			self.cpu.setAddSubFlag(bool(value))
		elif name == "fC":
			self.cpu.setCarryFlag(bool(value))
		elif name == "A":
			self.cpu.setRegA(value)
		elif name == "B":
			self.cpu.setRegB(value)
		elif name == "C":
			self.cpu.setRegC(value)
		elif name == "D":
			self.cpu.setRegD(value)
		elif name == "E":
			self.cpu.setRegE(value)
		elif name == "H":
			self.cpu.setRegH(value)
		elif name == "L":
			self.cpu.setRegL(value)
		elif name == "PC":
			self.cpu.setRegPC(value)
		elif name == "SP":
			self.cpu.setRegSP(value)
		elif name == "IX":
			self.cpu.setRegIX(value)
		elif name == "IY":
			self.cpu.setRegIY(value)
		elif name == "I":
			self.cpu.setRegI(value)
		elif name == "R":
			self.cpu.setRegR(value)
		elif name == "HALT":
			self.cpu.setHalted(bool(value))
		elif name == "IFF1":
			self.cpu.setIFF1(bool(value))
		elif name == "IFF2":
			self.cpu.setIFF2(bool(value))
		elif name == "IM":
			self.cpu.setIM(i2im(value))
		elif name == "A_":
			self.cpu.setRegAx(value)
		elif name == "B_":
			self.cpu.setRegBx(value)
		elif name == "C_":
			self.cpu.setRegCx(value)
		elif name == "D_":
			self.cpu.setRegDx(value)
		elif name == "E_":
			self.cpu.setRegEx(value)
		elif name == "H_":
			self.cpu.setRegHx(value)
		elif name == "L_":
			self.cpu.setRegLx(value)
		
	def getRegistersDefinition(self):
		return [
			["Main", [["A","A",8],["B","B",8],["C","C",8],["D","D",8],["E","E",8],["H","H",8],["L","L",8]]],
			["Special", [["PC","PC",16],["SP","SP",16],["IX","IX",16],["IY","IY",16],["I","I",8],["R","R",8]]],
			["Flags", [["fS","Sign",1],["fZ","Zero",1],["fH","Half Carry",1],["fPV","Parity/Overflow",1],["fN","Add/Subtract",1],["fC","Carry",1]]],
			["Other",[["HALT","HALT",1],["IFF1","IFF1",1],["IFF2","IFF2",1],["IM","IM",1]]],
			["Shadow", [["A_","A'",8],["B_","B'",8],["C_","C'",8],["D_","D'",8],["E_","E'",8],["H_","H'",8],["L_","L'",8]]],
			["Shadow Flags", [["fS_","Sign'",1],["fZ_","Zero'",1],["fH_","Half Carry",1],["fPV_","Parity/Overflow'",1],["fN_","Add/Subtract'",1],["fC_","Carry'",1]]],
			]

	def getProgramCounter(self):
		return self.cpu.getRegPC()

	def getStackPointerName(self):
		return "SP"

	def getState(self):
		state = struct.pack(">BBBBBBBBBHHHHBBBBBBBBBBBBB",
			self.cpu.getRegFx(),self.cpu.getFlags(),self.cpu.getRegA(),
			self.cpu.getRegB(),self.cpu.getRegC(),
			self.cpu.getRegD(),self.cpu.getRegE(),
			self.cpu.getRegH(),self.cpu.getRegL(),
			self.cpu.getRegPC(),self.cpu.getRegSP(),
			self.cpu.getRegIX(),self.cpu.getRegIY(),
			self.cpu.getRegI(),self.cpu.getRegR(),
			int(self.cpu.isHalted()),int(self.cpu.isIFF1()),int(self.cpu.isIFF2()),
			im2i(self.cpu.getIM()),self.cpu.getRegAx(),
			self.cpu.getRegBx(),self.cpu.getRegCx(),
			self.cpu.getRegDx(),self.cpu.getRegEx(),
			self.cpu.getRegHx(),self.cpu.getRegLx())
		return state
	
	def setState(self,state):
		value = struct.unpack(">BBBBBBBBBHHHHBBBBBBBBBBBBB",state)
		self.cpu.setRegFx(value[0])
		self.cpu.setFlags(value[1])
		self.cpu.setRegA(value[2])
		self.cpu.setRegB(value[3])
		self.cpu.setRegC(value[4])
		self.cpu.setRegD(value[5])
		self.cpu.setRegE(value[6])
		self.cpu.setRegH(value[7])
		self.cpu.setRegL(value[8])
		self.cpu.setRegPC(value[9])
		self.cpu.setRegSP(value[10])
		self.cpu.setRegIX(value[11])
		self.cpu.setRegIY(value[12])
		self.cpu.setRegI(value[13])
		self.cpu.setRegR(value[14])
		self.cpu.setHalted(bool(value[15]))
		self.cpu.setIFF1(bool(value[16]))
		self.cpu.setIFF2(bool(value[17]))
		self.cpu.setIM(i2im(value[18]))
		self.cpu.setRegAx(value[19])
		self.cpu.setRegBx(value[20])
		self.cpu.setRegCx(value[21])
		self.cpu.setRegDx(value[22])
		self.cpu.setRegEx(value[23])
		self.cpu.setRegHx(value[24])
		self.cpu.setRegLx(value[25])
