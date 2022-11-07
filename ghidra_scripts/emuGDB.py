# GDB Bridge
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.EmulatorFrame import EmulatorFrame
from emulators.archgdb.bridge import Bridge
from javax.swing import JOptionPane

target = JOptionPane.showInputDialog("Enter GDB target:","localhost:2323");
if target != None:
	bridge = Bridge(getState())
	bridge.setTarget(target)
	regs = bridge
	cpu  = bridge
	mem = bridge
	archName = str(getState().getCurrentProgram().getLanguage().getProcessor())
	EmulatorFrame("%s GDB Bridge" % archName, cpu, regs, mem, getState())
