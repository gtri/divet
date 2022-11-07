# Trace Function Call Visualization
#@author Daniel Tabor
#@category Emulation
#@keybinding
#@menupath
#@toolbar

from emulators.FunctionCallVisualization import TraceFrame

frame = TraceFrame(getState())
frame.show()
