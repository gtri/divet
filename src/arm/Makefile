armcore.jar: armcore/Memory.java armcore/Arm.java
	mkdir -p build
	javac -d build armcore/Memory.java
	javac -d build armcore/Arm.java
	jar cf armcore.jar -C build armcore/

install: armcore.jar
	cp armcore.jar ../../ghidra_scripts/emulators/archarm/
	

clean:
	rm -f armcore.jar
	rm -rf build
