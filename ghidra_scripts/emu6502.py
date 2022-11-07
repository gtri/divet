# MOS6502 Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.EmulatorFrame import EmulatorFrame
from emulators.EndianEmulatedMemory import LittleEndianEmulatedMemory
from emulators.arch6502.cpu import Registers,CPU

mem  = LittleEndianEmulatedMemory(currentProgram, 16, 0, historySize=1024)
regs = Registers()
cpu  = CPU(regs, mem)
EmulatorFrame("6502 Emulator", cpu, regs, mem, getState())
