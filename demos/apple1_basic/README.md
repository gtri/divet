**INSTALLATION:**

1) This demo was developed using Ghidra 9.1.2 PUBLIC.  So, first of all install that.

2) Copy the contents of the project ghidra_scripts directory into your local ghidra_scripts direction.  On both Linux and Windows the location of this directory defaults to your home directory. On macOS the directory is your user directory.

**RUNNING THE DEMO:**

1) Start Ghidra and "Restore" the project apple1_eprom.gar.

2) There is only a single image in the project, open it up in the CodeBrowser by double-clicking on it.  It is a EEPROM image from an [Apple I clone](https://www.youtube.com/watch?v=ZXllm5JWWAs)

3) Open the Script Manager (Click Window->Script Manager)

4) On the Categories to the left-side of the Script Manager, you should see "Emulation".  If you don't then you didn't copy the scripts to the correct place.  Select the Emulation category, and you should see emu6502.py. Double-click emu6502.py to run it.  You should see a window open up with the title "6502 Emulator".

5) Open up an emulation run configuration.  Click the "Load Config" button, and open the hello_world.demo.  You should see the PC register change to E000, and you should see some stuff appear in the Watch Memory area.

6) You can see the emulator run by clicking the "Cont" button.  Try to have the CodeBrowser window view-able at the same time as the emulator window, so you can see the two interact.

**UNDERSTANDING THE DEMO:**

This demo is literally a "HELLO WORLD" demonstration.  We're interacting with the BASIC prompt on the emulated Apple I.  Two of the addresses that I've included in the initial watch list are just labeled code (E000 - the beginning of BASIC, E2B6 - Right before BASIC displays a prompt).  The other three addresses are memory mapped IO, and we will have to simulate other hardware in order to get the code working properly, which is why they have "Read Values" specified.  Whenever the CPU reads those memory addresses it will read the values shown in order, and cycle back to the beginning when they have all been read.

**D010** ConsoleInput is how user keyboard input is brought into the system.  Keyboard input is _almost_ ASCII, but it's a bit tricky because the Apple I sets the high bit as part of some external signaling.  So, if you were to mask off the most significant bit of all the bytes there, they would read: PRINT "HELLO WORLD"[CR].

**D011** ConsoleInputCtrl is a control register for the PIA chip.  It's high bit is set when data is waiting.  So always reading 0x80, means the computer never waits for more input.

**D0F2** BASIC_ConsoleOuptut_Mirror is where the system writes output to go the monitor.  It's actually equivalent to D012, but the way the CPU is wired up to PIA chips, the four relevant IO addresses are mirrored all throughout the Dxxx space.  The system will read this address, and if the high bit is set, then it means a character is still waiting to be fetched by the video circuitry.  So, whenever this address is read, it will read 0x00, so the system won't wait to output characters.  Similarly to the input, the high bit on all output bytes is set as well.  This is the address we need to watch to see the "results" of the demo.

When you first hit the Cont button the system will execute until it hits the address E2B6.  It will then break, because it is checked as a Breakpoint in the memory area.  The second time you hit the Cont button the BASIC interpreter will print out a prompt and then read our line of input, echoing each character to D0F2 as it does.  It will then go into the long process of compiling the line of code and then executing.  This will take some time, but eventually, once it's done compiling, it will print HELLO WORLD[CR] back out again. (That's  C8, C5, CC, CC, CF, A0, D7, CF, D2, CC, C4, 8D because the high bit is set).  It will then Break automatically when it reaches E2B6 again.
