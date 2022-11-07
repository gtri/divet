package m68k.cpu;

import m68k.memory.AddressSpace;
import m68k.TaintedValue;

/*
//  M68k - Java Amiga MachineCore
//  Copyright (c) 2008-2010, Tony Headford
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
//  following conditions are met:
//
//    o  Redistributions of source code must retain the above copyright notice, this list of conditions and the
//       following disclaimer.
//    o  Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
//       following disclaimer in the documentation and/or other materials provided with the distribution.
//    o  Neither the name of the M68k Project nor the names of its contributors may be used to endorse or promote
//       products derived from this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
//  INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
*/
public interface Cpu
{
	public static final int C_FLAG = 1;
	public static final int V_FLAG = 2;
	public static final int Z_FLAG = 4;
	public static final int N_FLAG = 8;
	public static final int X_FLAG = 16;
	public static final int INTERRUPT_FLAGS_MASK = 0x0700;
	public static final int SUPERVISOR_FLAG = 0x2000;
	public static final int TRACE_FLAG = 0x8000;

	public void setAddressSpace(AddressSpace memory);
	public void reset();
	public void resetExternal();
	public void stop();
	public int execute();
	
	// data registers
	public TaintedValue getDataRegisterByte(int reg);
	public TaintedValue getDataRegisterByteSigned(int reg);
	public TaintedValue getDataRegisterWord(int reg);
	public TaintedValue getDataRegisterWordSigned(int reg);
	public TaintedValue getDataRegisterLong(int reg);
	public void setDataRegisterByte(int reg, TaintedValue value);
	public void setDataRegisterWord(int reg, TaintedValue value);
	public void setDataRegisterLong(int reg, TaintedValue value);
	// address registers
	public TaintedValue getAddrRegisterByte(int reg);
	public TaintedValue getAddrRegisterByteSigned(int reg);
	public TaintedValue getAddrRegisterWord(int reg);
	public TaintedValue getAddrRegisterWordSigned(int reg);
	public TaintedValue getAddrRegisterLong(int reg);
	public void setAddrRegisterByte(int reg, TaintedValue value);
	public void setAddrRegisterWord(int reg, TaintedValue value);
	public void setAddrRegisterLong(int reg, TaintedValue value);
	//memory interface
	public TaintedValue readMemoryByte(int addr);
	public TaintedValue readMemoryByteSigned(int addr);
	public TaintedValue readMemoryWord(int addr);
	public TaintedValue readMemoryWordSigned(int addr);
	public TaintedValue readMemoryLong(int addr);
	public void writeMemoryByte(int addr, TaintedValue value);
	public void writeMemoryWord(int addr, TaintedValue value);
	public void writeMemoryLong(int addr, TaintedValue value);
	//addr reg helpers
	public void incrementAddrRegister(int reg, int numBytes);
	public void decrementAddrRegister(int reg, int numBytes);
	
	// PC reg
	public TaintedValue getPC();
	public void setPC(TaintedValue address);
	// pc fetches - for reading data following instructions and incrementing the PC afterwards
	public TaintedValue fetchPCWord();
	public TaintedValue fetchPCWordSigned();
	public TaintedValue fetchPCLong();
	// status reg
	public boolean isSupervisorMode();
	public int getCCRegister();
	public int getSR();
	public void setCCRegister(int value);
	public void setSR(int value);
	public void setSR2(int value);
	//flags
	public void setFlags(int flags);
	public void clrFlags(int flags);
	public boolean isFlagSet(int flag);
	public void calcFlags(InstructionType type, int s, int d, int r, Size sz);
	public void calcFlagsParam(InstructionType type, int s, int d, int r, int extraParam, Size sz);
	public boolean testCC(int cc);

	// stacks
	public TaintedValue getUSP();
	public void setUSP(TaintedValue address);
	public TaintedValue getSSP();
	public void setSSP(TaintedValue address);
	public void pushWord(TaintedValue value);
	public void pushLong(TaintedValue value);
	public TaintedValue popWord();
	public TaintedValue popLong();
	
	// exceptions & interrupts
	public void raiseException(int vector);
	public void raiseSRException();
	public void raiseInterrupt(int priority);
	public int getInterruptLevel();

	//source EA
	public Operand resolveSrcEA(int mode, int reg, Size sz);
	// destination EA
	public Operand resolveDstEA(int mode, int reg, Size sz);

	// disassembling
	public Instruction getInstructionAt(int address);
	public Instruction getInstructionFor(int opcode);
	public DisassembledOperand disassembleSrcEA(int address, int mode, int reg, Size sz);
	public DisassembledOperand disassembleDstEA(int address, int mode, int reg, Size sz);
}
