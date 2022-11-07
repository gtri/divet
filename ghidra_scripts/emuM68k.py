# Motorola 68k Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.archm68k.cpu import Registers,CPU
from emulators.EndianEmulatedMemory import BigEndianEmulatedMemory
from emulators.EmulatorFrame import EmulatorFrame

mem  = BigEndianEmulatedMemory(currentProgram, 32, 0, historySize=1024)
regs = Registers()
cpu  = CPU(regs, mem)
EmulatorFrame("m68k Emulator", cpu, regs, mem, getState())