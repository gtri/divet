# TI MSP340 Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.EmulatorFrame import EmulatorFrame
from emulators.EndianEmulatedMemory import LittleEndianEmulatedMemory
from emulators.archmsp430.cpux import RegistersX,CPUX

mem  = LittleEndianEmulatedMemory(currentProgram,20,0,historySize=1024)
regs = RegistersX()
cpu  = CPUX(regs,mem)
EmulatorFrame("MSP430X Emulator",cpu,regs,mem,getState())
