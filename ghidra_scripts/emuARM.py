# ARM Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.archarm.cpu import CPU
from emulators.EndianEmulatedMemory import LittleEndianEmulatedMemory
from emulators.EmulatorFrame import EmulatorFrame

mem  = LittleEndianEmulatedMemory(currentProgram, 32, 0, historySize=1024)
cpu  = CPU(mem)
regs = cpu
EmulatorFrame("ARM Emulator", cpu, regs, mem, getState())