What is DIVET?
==============

DIVET is an emulator plugin for Ghidra to allow for dynamic analysis using the static binaries analyzed within the database itself. All identified functions, symbols, and names are maintained. This minimizes the environment switching from static analysis to a different emulation environment or live hardware debugging.

Features
--------
- Dynamic analysis of algorithms without a debugger
- Forward and reverse execution
- Breakpoints and conditionals
- Tainted value tracing
- Execution tracing and visualization
- Emulated memory with banking
- Generalized emulator framework
- P-code emulation
- Scripting support


Installation
============

1) Install Ghidra. [Ghidra 9.1.2 PUBLIC](https://ghidra-sre.org/releaseNotes_9.1.2.html) is recommended. Other versions may function but are untested.

2) Copy the contents of the `ghidra_scripts` directory into your local `ghidra_scripts` location.  On both Linux and Windows, the location of this directory defaults to your home directory. On macOS, the directory is your user directory.

Running the Emulator
====================

1) Start Ghidra and open the project and the binary to emulate.

2) Open the Script Manager (Click `Window`->`Script Manager`).  On the toolbar it is the icon with green circle and white triangle.

3) On the Categories to the left-side of the Script Manager, you should see `Emulation`.  If you don't then make sure you copied the `ghidra_scripts` contents to the correct location.  Select the Emulation category, and you should see several emulators. Double-click the desired emulator to run.

5) Optionally open up an emulation run configuration.  Click the `Load Config` button, and select the desired configuration file.  Depending on what is in the configuration, items will populate in the `Watch Memory` panel, and registers will change on the `Registers` panel.

6) Individual instructions can be stepped through via the `Step` button. The `Cont` button will run the until code the user presses 'Break' or until a breakpoint is hit.

Understanding the Emulator
==========================

Registers Panel
---------------
The registers panel contains all the registers and flags for the selected emulator architecture. Each architecture has a set of registers and flags that determine the processor state. As the emulator executes an instruction, it will use the displayed values, and will update the panel with the new values upon completion. Anytime one of the flags or registers updates, the box will be colored yellow for that cycle.
The `Reset` button will reset all the registers and flags to their default values. The `Update` button will update the next displayed instruction based on the register values.

Emulator Controls
-----------------
- The `Step` button will execute a single instruction, updating the program state accordingly.
- The `Cont` button will continuously execute instructions until the 'Break' button is pressed or a breakpoint is encountered.
- The `Break` button will manually break execution of the emulator.
- The `Unstep` button will reverse execution of an instruction.
[TODO:  To check with Dan about history length, the drop-down, and signal.]
- The `Start Trace` button will prompt the user for a file save location. Upon this, executing an instruction will record the execution in a trace file.
[TODO:  Check if changes to the memory or UI are recorded.]
- The `Stop Trace` button will stop recording execution.
- The `Save Config` button saves the current states of registers, watch memory, and breakpoints to a config file.
- The `Load Config` button loads a config file and populates the emulator state with register values, watch memory, and breakpoints.

Break Conditions Panel
----------------------
The break conditions panel is a list of breakpoints when to pause continuous execution of the emulator.
- The `Enabled` checkbox enables the breakpoint.
- The `Triggered` checkbox will automatically be checked when the emulator detects the breakpoint has been triggered.
- The `Script` textbox is the condition by which the breakpoint will occur. The conditions are defined by the following set of rules. `<>` denotes following another rule, `[]` denotes a value the user types. `|` denotes multiple valid uses.

|   Input Type   |                     Syntax                     |
| -------------- | ---------------------------------------------- |
|   `<script>`   | `<access>` `<condition>` `<watchValue>`        |
|   `<access>`   | `<memAccess>` \| `<regAccess>` \| `<bpAccess>` |
|  `<memAccess>` | `<accessType>` `[bank name]` `<target>`        |
|  `<regAccess>` | `REG` `[register name]`                        |
|  `<bpAccess>`  | `BP`                                           |
| `<accessType>` | `R` \| `W` \| `RW`                             |
|   `<target>`   | `<range>` \| `<set>`                           |
|    `<range>`   | `<start>` - `<end>`                            |
|    `<start>`   | `MIN` \| `<item>`                              |
|     `<end>`    | `MAX` \| `<item>`                              |
|     `<set>`    | `<item>` \| `<item>`, `<item>`, ...            |
|    `<item>`    | `[symbol name]` \| `[address]`                 |
|  `<condition>` | `<=` \| `<` \| `==` \| `>=` \| `>`             |
| `<watchValue>` | `<item>` \| `<item>` `<tainted>`               |
|   `<tainted>`  | `T` \| `U`                                     |
    - Example:  to add a breakpoint for when register A is less than 0x30, the script would be `BP REG A < 0x30`
    - Example:  to add a breakpoint for when memory address 0x123 in the MEM bank is less than 0x8 , the script would be `R MEM 0x123 < 0x8"
	


Watch Memory Panel
------------------
The watch memory panel is a list of memory locations to monitor during execution. To add a memory location to monitor, use the top row in the panel.
- The text box is the address to add to the list. The address is in hexadecimal, supporting both with and without the '0x' syntax.
- The first dropdown box is the memory type of the item to monitor. Supported memory types are `byte` (8 bits), `word` (16 bits), `dword` (32 bits), and `qword` (64 bits).
- The second dropdown box is for selecting which bank of memory to monitor. Some processors have different memory spaces for program, I/O, and others.
- The `Add` button will add the new memory location to the list. The location will only be added if there is no item already in the list with the same address, bank, and memory size.
- The `Remove` button will remove the currently selected memory location (in the table) from the panel.

The second row contains options for the memory panel as a whole.
- The `Watch on write` checkbox will enable automatic addition of memory locations to the memory list upon write operations.
- The `Watch on tainted write` checkbox will enable automatic addition of memory locations to the memory list upon write operations with data that was flagged as 'tainted'. Tainted memory is a way of tracking data dependencies upon writes.
- The `Watch on read` checkbox will enable automatic addition memory locations to the memory list upon memory read operations.
- The `HexDump` button will open up a memory dump of the memory space.
    - The `Bank` dropdown selects which memory bank to display.
    - The `Offset` box chooses the starting offset address for the rows.
    - The `ByteWidth` box chooses the number of bytes displayed in each column.
    - The `BufferSize` box chooses the total number of bytes to display in the window.
    - The `Decay` box chooses the number of steps (cycles) that a change is highlighted for.

The third row contains options for the default behavior of memory.
- The `Default Read` box is the default value that any memory space will return upon a read, unless it has another value specified.
- The `Update Default` button will update the default value. If a memory item in the table doesn't yet have a value, it will be given the new default value.
- The `Toggle Mutable` button will toggle the mutable state of all selected cells in the table.
- The `Reset` button will reset the entire emulated memory back to an initial state. It does not take into account any configurations that are loaded.

The memory table has two tabs, `Memory` and `Access`.
- The `Memory` tab lists the current memory addresses under watch.
    - The `Bank` is which memory bank the watched memory belongs to.
    - The `Address` is which address (in hexadecimal) the memory is located at.
    - The `Label` is the label given to the memory in the Ghidra database.
    - The `Data Type` is the type of the watched memory as defined in the Ghidra database.
    - The `Current Value` is the value at that address as defined in the current program state.
    - The `R/W` box is which memory operation was performed on that address in the current execution step.
    - The `Mutable` box enables write operations to change the currently tracked value.
    - The `Tainted` box tracks if the memory location is marked as tainted. Memory will be marked as tainted if their value depended on some other tainted memory.
    - The `Stored Value` box is the last value that was written to the address. For a non-mutable address, the `Current Value` and `Stored Value` may be two distinct values.
    - The `Read Values` box is a list of values to read in round-robin style. This is intended to emulate memory-mapped I/O, such as an input from a serial line.
- The `Access` tab lists memory addresses that have been accessed by the program.
    - [TODO:  Need to get examples]

Scripting Panel
---------------
The scripting panel is a command line-esque interface with two separate operating modes. It is intended to allow for quick memory edits in Database mode, or to allow for more complex operations in Python mode.
- The `Output` area is where the command results will be displayed, from both operating modes.
- The `Py/DB` button will change the command line mode between Python and Database mode.
    - Python mode acts as a Python interpreter. There are API hooks available to modify fields in the emulator. [TODO:  List out the API hooks available]
    - Database mode acts as a C-style command interface for modifying memory. It supports C-style math operations and pointer arithmetic. It also supports variables. Order of operations are currently not supported, and any complex math should use parentheses to ensure correct calculations. [TODO: List out the possible commands, likely in the same file as the API hooks]
- The `Enter` button will input the command. You can also press the Enter key.
- The `Browse` button is only available in Python mode. It will execute the chosen file, executing each line as if it were entered in the command line.


