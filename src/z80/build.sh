#!/bin/bash
if [ "$1" = "clean" ]; then
	rm -rf build
else

	mkdir -p build
	javac -d build z80core/MemIoOps.java
	javac -d build z80core/NotifyOps.java
	javac -d build z80core/Z80.java
	javac -d build z80core/Z80State.java
	jar cf ../../ghidra_scripts/emulators/archz80/z80core.jar -C build z80core/
fi
