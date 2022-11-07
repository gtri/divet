# Zilog 80 Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.EmulatorFrame import EmulatorFrame
from emulators.EndianEmulatedMemory import LittleEndianEmulatedMemory
from emulators.archz80.cpu import CPU
from emulators.archz80.registers import Registers

mem  = LittleEndianEmulatedMemory(currentProgram, 16, 0, historySize=1024)
mem.addBank("IO",0,0xFFFF)
regs = Registers()
cpu  = CPU(regs, mem)
EmulatorFrame("Z80 Emulator", cpu, regs, mem, getState())
