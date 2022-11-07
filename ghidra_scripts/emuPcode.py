# Pcode Emulator
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.EmulatorFrame import EmulatorFrame
from emulators.archpcode.cpu import CPU
from emulators.archpcode.registers import Registers

regs = Registers(getState())
cpu  = CPU(regs, getState())
mem = cpu.getEmulatedMemory()
archName = str(getState().getCurrentProgram().getLanguage().getProcessor())
EmulatorFrame("%s (Pcode) Emulator" % archName, cpu, regs, mem, getState())
