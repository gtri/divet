import struct
from util import taintName

class BitAccesser(object):
	def __init__(self, bit_names, registers, reg):
		object.__setattr__(self, "bits",
						   dict(zip(bit_names, range(7, -1, -1))))
		self.registers = registers
		#self.registers = registers
		self.reg = reg
		
	def __getattr__(self, b):
		return (self.registers[self.reg] >>  self.bits[b]) &  1 
	
	def __setattr__(self, b, v):
		if not b in self.bits:
			object.__setattr__(self, b, v)
			return

		if v:
			self.registers[self.reg] = self.registers[self.reg] | (1 <<  self.bits[b])
		else:
			self.registers[self.reg] = self.registers[self.reg] & ((1 <<  self.bits[b]) ^  0xFF)
			
class Registers(dict):
	def __init__(self, *arg, **kw):
		super(Registers, self).__init__(*arg, **kw)
		self.reset(True)
		
	def reset(self,pinReset=False):
		if pinReset:
			self["A"] = 0xFF # Accumulator (8bit)
			self["A_taint"] = 0
			self["F"] = 0xFF # Flags (8bit)
			self["F_taint"] = 0
			self["A_"] = 0xFF # Alt. Accumulator (8bit)
			self["A__taint"] = 0
			self["F_"] = 0xFF # Alt. Flags (8bit)
			self["F__taint"] = 0

			self["B"] = 0xFF # General (8bit)
			self["B_taint"] = 0
			self["C"] = 0xFF # General (8bit)
			self["C_taint"] = 0
			self["B_"] = 0xFF # General (8bit)
			self["B__taint"] = 0
			self["C_"] = 0xFF # General (8bit)
			self["C__taint"] = 0

			self["D"] = 0xFF # General (8bit)
			self["D_taint"] = 0
			self["E"] = 0xFF # General (8bit)
			self["E_taint"] = 0
			self["D_"] = 0xFF # General (8bit)
			self["D__taint"] = 0
			self["E_"] = 0xFF # General (8bit)
			self["E__taint"] = 0

			self["H"] = 0xFF # General (8bit)
			self["H_taint"] = 0
			self["L"] = 0xFF # General (8bit)
			self["L_taint"] = 0
			self["H_"] = 0xFF # General (8bit)
			self["H__taint"] = 0
			self["L_"] = 0xFF # General (8bit)
			self["L__taint"] = 0
			self["SP"] = 0xFFFF # Stack Pointer (16bit)
			self["SP_taint"] = 0
			self["IX"] = 0xFFFF # Index Register X (16bit)
			self["IX_taint"] = 0
			self["IY"] = 0xFFFF # Index Register Y (16bit)
			self["IY_taint"] = 0
		
		self["PC"] = 0 # Program Counter (16bit)
		self["PC_taint"] = 0
		self["I"] = 0  # Interrupt Page Address (8bit)
		self["I_taint"] = 0
		self["R"] = 0  # Memory Refresh (8bit)
		self["R_taint"] = 0

		self["condition"] = BitAccesser(["S", "Z", "F5", "H", "F3", "PV", "N", "C"], self, "F")
		self["condition_"] = BitAccesser(["S_", "Z_", "F5_", "H_", "F3_", "PV_", "N_", "C_"], self, "F_")
		
		self['HALT']=False #
		self['IFF']=False  # Interrupt flip flop
		self['IFF2']=False  # NM Interrupt flip flop
		self['IM']=False   # Iterrupt mode

	def __setattr__(self, attr, val):
		if attr  in ["HL", "AF", "BC", "DE"]:
			self[attr[0]] = val >> 8
			self[attr[1]] = val &  0xFF
		elif attr in ["HL_taint","AF_taint","BC_taint","DE_taint"]:
			self[taintName(attr[0])] = val
			self[taintName(attr[1])] = val
		else:
			self[attr] = val

	def __getattr__(self, reg):
		if self.has_key(reg):
			return self[reg]
		elif reg in ["HL", "AF", "BC", "DE"]:
			return self[reg[0]] << 8 |  self[reg[1]]
		elif reg in ["HL_taint","AF_taint","BC_taint","DE_taint"]:
			return self[taintName(reg[0])] | self[taintName(reg[1])]
		else:
			raise AttributeError("%s Not a known register."%reg)
		
	def __getitem__(self, reg):
		if reg in ["BC", "HL", "DE", "AF"]:
			return getattr(self, reg)
		elif reg in ["BC_taint","HL_taint","DE_taint","AF_taint"]:
			return getattr(self,reg)
		else:
			return super(Registers, self).__getitem__(reg)
		
	def __setitem__(self, reg, val):
		if reg in ["BC", "HL", "DE", "AF"]:
			return setattr(self, reg, val)
		elif reg in ["BC_taint","HL_taint","DE_taint","AF_taint"]:
			return setattr(self, reg, val)
		else:
			return super(Registers, self).__setitem__(reg, val)
	
	@classmethod
	def create(cls):
		return cls()
	
	def getRegister(self,name):
		if name[0] == "f" and hasattr(self.condition,name[1:]):
			value = getattr(self.condition,name[1:])
			taint = self.F_taint
		elif name[0] == "f" and hasattr(self.condition_,name[1:]):
			value = getattr(self.condition_,name[1:])
			taint = self.F__taint
		elif hasattr(self,name):
			value = getattr(self,name)
			if name in ["HALT","IFF","IFF2","IM"]:
				if value: value = 1
				else: value = 0
				taint = 0
			else:
				taint = getattr(self,taintName(name))
		else:
			raise ValueError,"Unknown register: %s" % name
		return value,taint
		
	def setRegister(self,name,value,taint):
		if name[0] == "f" and hasattr(self.condition,name[1:]):
			setattr(self.condition,name[1:],value)
			self.F_taint = taint
		elif name[0] == "f" and hasattr(self.condition_,name[1:]):
			setattr(self.condition_,name[1:],value)
			self.F__taint = taint
		elif hasattr(self,name):
			if name in ["HALT","IFF","IFF2","IM"]:
				if value:
					setattr(self,name,1)
				else:
					setattr(self,name,0)
			else:
				setattr(self,name,value)
				setattr(self,taintName(name),taint)
		
	def getRegistersDefinition(self):
		return [
			["Main", [["A","A",8],["B","B",8],["C","C",8],["D","D",8],["E","E",8],["H","H",8],["L","L",8]]],
			["Special", [["PC","PC",16],["SP","SP",16],["IX","IX",16],["IY","IY",16],["I","I",8],["R","R",8]]],
			["Flags", [["fS","Sign",1],["fZ","Zero",1],["fH","Half Carry",1],["fPV","Parity/Overflow",1],["fN","Add/Subtract",1],["fC","Carry",1]]],
			["Other",[["HALT","HALT",1],["IFF","IFF",1],["IFF2","IFF2",1],["IM","IM",1]]],
			["Shadow", [["A_","A'",8],["B_","B'",8],["C_","C'",8],["D_","D'",8],["E_","E'",8],["H_","H'",8],["L_","L'",8]]],
			["Shadow Flags", [["fS_","Sign'",1],["fZ_","Zero'",1],["fH_","Half Carry",1],["fPV_","Parity/Overflow'",1],["fN_","Add/Subtract'",1],["fC_","Carry'",1]]],
			]

	def getProgramCounter(self):
		return self["PC"]

	def getStackPointerName(self):
		return "SP"

	def getState(self):
		if self['HALT']: halt=1
		else: halt = 0
		if self['IFF']: iff=1
		else: iff = 0
		if self['IFF2']: iff2=1
		else: iff2=0
		if self['IM']: im=1
		else: im = 0
		state = struct.pack(">HIHIHIHIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBBBB",self["PC"],self["PC_taint"],self["SP"],self["SP_taint"],self["IX"],self["SP_taint"],self["IY"],self["IY_taint"],self["I"],self["I_taint"],self["R"],self["R_taint"],self["A"],self["A_taint"],self["F"],self["F_taint"],self["A_"],self["A__taint"],self["F_"],self["F__taint"],self["B"],self["B_taint"],self["C"],self["C_taint"],self["B_"],self["B__taint"],self["C_"],self["C__taint"],self["D"],self["D_taint"],self["E"],self["E_taint"],self["D_"],self["D__taint"],self["E_"],self["E__taint"],self["H"],self["H_taint"],self["L"],self["L_taint"],self["H_"],self["H__taint"],self["L_"],self["L__taint"],halt,iff,iff2,im)
		return state
		
	def setState(self,state):
		self["PC"],self["PC_taint"],self["SP"],self["SP_taint"],self["IX"],self["SP_taint"],self["IY"],self["IY_taint"],self["I"],self["I_taint"],self["R"],self["R_taint"],self["A"],self["A_taint"],self["F"],self["F_taint"],self["A_"],self["A__taint"],self["F_"],self["F__taint"],self["B"],self["B_taint"],self["C"],self["C_taint"],self["B_"],self["B__taint"],self["C_"],self["C__taint"],self["D"],self["D_taint"],self["E"],self["E_taint"],self["D_"],self["D__taint"],self["E_"],self["E__taint"],self["H"],self["H_taint"],self["L"],self["L_taint"],self["H_"],self["H__taint"],self["L_"],self["L__taint"],halt,iff,iff2,im = struct.unpack(">HIHIHIHIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBIBBBB",state)
		self['HALT'] = (halt == 1)
		self['IFF'] = (iff == 1)
		self['IFF2'] = (iff2 == 1)
		self['IM'] = (im == 1)
		