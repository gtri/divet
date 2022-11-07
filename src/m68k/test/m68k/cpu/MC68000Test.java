package m68k.cpu;

import junit.framework.TestCase;
import m68k.memory.AddressSpace;
import m68k.memory.MemorySpace;
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
public class MC68000Test extends TestCase
{
	AddressSpace bus;
	Cpu cpu;

	public void setUp()
	{
		bus = new MemorySpace(1);	//create 1kb of memory for the cpu
		cpu = new MC68000();
		cpu.setAddressSpace(bus);
		cpu.reset();
	}

	public void testDataRegs()
	{
		for(int r = 0; r < 7; r++)
		{
			cpu.setDataRegisterByte(r, new TaintedValue(0xaa,0));
			assertEquals(0xaa, cpu.getDataRegisterByte(r).value);
			assertEquals(0xaa, cpu.getDataRegisterWord(r).value);
			assertEquals(0xaa, cpu.getDataRegisterLong(r).value);
			assertEquals(0xffffffaa, cpu.getDataRegisterByteSigned(r).value);
			assertEquals(0x000000aa, cpu.getDataRegisterWordSigned(r).value);

			cpu.setDataRegisterWord(r, new TaintedValue(0xa5a5,0));
			assertEquals(0xa5, cpu.getDataRegisterByte(r).value);
			assertEquals(0xa5a5, cpu.getDataRegisterWord(r).value);
			assertEquals(0xa5a5, cpu.getDataRegisterLong(r).value);
			assertEquals(0xffffffa5, cpu.getDataRegisterByteSigned(r).value);
			assertEquals(0xffffa5a5, cpu.getDataRegisterWordSigned(r).value);

			cpu.setDataRegisterLong(r, new TaintedValue(0x85858585,0));
			assertEquals(0x85, cpu.getDataRegisterByte(r).value);
			assertEquals(0x8585, cpu.getDataRegisterWord(r).value);
			assertEquals(0x85858585, cpu.getDataRegisterLong(r).value);
			assertEquals(0xffffff85, cpu.getDataRegisterByteSigned(r).value);
			assertEquals(0xffff8585, cpu.getDataRegisterWordSigned(r).value);

			cpu.setDataRegisterLong(r, new TaintedValue(0x12345678,0));
			assertEquals(0x78, cpu.getDataRegisterByte(r).value);
			assertEquals(0x5678, cpu.getDataRegisterWord(r).value);
			assertEquals(0x12345678, cpu.getDataRegisterLong(r).value);
			assertEquals(0x78, cpu.getDataRegisterByteSigned(r).value);
			assertEquals(0x5678, cpu.getDataRegisterWordSigned(r).value);
		}
	}

	public void testAddrRegs()
	{
		for(int r = 0; r < 7; r++)
		{
			cpu.setAddrRegisterByte(r, new TaintedValue(0xaa,0));
			assertEquals(0xaa, cpu.getAddrRegisterByte(r).value);
			assertEquals(0xaa, cpu.getAddrRegisterWord(r).value);
			assertEquals(0xaa, cpu.getAddrRegisterLong(r).value);
			assertEquals(0xffffffaa, cpu.getAddrRegisterByteSigned(r).value);
			assertEquals(0x000000aa, cpu.getAddrRegisterWordSigned(r).value);

			cpu.setAddrRegisterWord(r, new TaintedValue(0xa5a5,0));
			assertEquals(0xa5, cpu.getAddrRegisterByte(r).value);
			assertEquals(0xa5a5, cpu.getAddrRegisterWord(r).value);
			assertEquals(0xa5a5, cpu.getAddrRegisterLong(r).value);
			assertEquals(0xffffffa5, cpu.getAddrRegisterByteSigned(r).value);
			assertEquals(0xffffa5a5, cpu.getAddrRegisterWordSigned(r).value);

			cpu.setAddrRegisterLong(r, new TaintedValue(0x85858585,0));
			assertEquals(0x85, cpu.getAddrRegisterByte(r).value);
			assertEquals(0x8585, cpu.getAddrRegisterWord(r).value);
			assertEquals(0x85858585, cpu.getAddrRegisterLong(r).value);
			assertEquals(0xffffff85, cpu.getAddrRegisterByteSigned(r).value);
			assertEquals(0xffff8585, cpu.getAddrRegisterWordSigned(r).value);

			cpu.setAddrRegisterLong(r, new TaintedValue(0x12345678,0));
			assertEquals(0x78, cpu.getAddrRegisterByte(r).value);
			assertEquals(0x5678, cpu.getAddrRegisterWord(r).value);
			assertEquals(0x12345678, cpu.getAddrRegisterLong(r).value);
			assertEquals(0x78, cpu.getAddrRegisterByteSigned(r).value);
			assertEquals(0x5678, cpu.getAddrRegisterWordSigned(r).value);
		}
	}

	public void testPC()
	{
		bus.writeLong(4, new TaintedValue(0x12345678,0));
		cpu.setPC(new TaintedValue(4,0));
		int val = cpu.fetchPCLong().value;
		assertEquals(0x12345678, val);
		assertEquals(8, cpu.getPC().value);

		cpu.setPC(new TaintedValue(4,0));
		val = cpu.fetchPCWord().value;
		assertEquals(0x1234, val);
		assertEquals(6, cpu.getPC().value);
		val = cpu.fetchPCWord().value;
		assertEquals(0x5678, val);
		assertEquals(8, cpu.getPC().value);

		cpu.setPC(new TaintedValue(4,0));
		bus.writeLong(4, new TaintedValue(0x12348765,0));
		val = cpu.fetchPCWordSigned().value;
		assertEquals(0x1234, val);
		assertEquals(6, cpu.getPC().value);
		val = cpu.fetchPCWordSigned().value;
		assertEquals(0xffff8765, val);
		assertEquals(8, cpu.getPC().value);
	}

	public void testFlags()
	{
		cpu.setSR(0x27ff);
		assertTrue(cpu.isFlagSet(Cpu.C_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.V_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.Z_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.N_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.X_FLAG));
		assertTrue(cpu.isSupervisorMode());
		assertEquals(7, cpu.getInterruptLevel());
		
		cpu.setSR(0);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());

		cpu.setCCRegister(Cpu.C_FLAG);
		assertTrue(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());

		cpu.setCCRegister(Cpu.V_FLAG);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());

		cpu.setCCRegister(Cpu.Z_FLAG);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());

		cpu.setCCRegister(Cpu.N_FLAG);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());

		cpu.setCCRegister(Cpu.X_FLAG);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.N_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.X_FLAG));
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0, cpu.getInterruptLevel());
	}

	public void testException()
	{
		bus.writeLong(0x08, new TaintedValue(0x56789,0));
		bus.writeLong(0x0c, new TaintedValue(0x12345,0));
		bus.writeLong(0x10, new TaintedValue(0x23456,0));
		cpu.setPC(new TaintedValue(0x32,0));
		cpu.setSR(0x04);
		cpu.setAddrRegisterLong(7, new TaintedValue(0x0100,0));
		cpu.setSSP(new TaintedValue(0x0200,0));
		cpu.raiseException(2);
		assertEquals("pc", 0x56789, cpu.getPC().value);
		assertEquals("a7", 0x01fa, cpu.getAddrRegisterLong(7).value); // 0x0200 - push pc + push sr (6 bytes)
		assertEquals("usp", 0x0100, cpu.getUSP().value);
		assertTrue("supervisor", cpu.isSupervisorMode());
		int sr = cpu.popWord().value;
		int pc = cpu.popLong().value;
		assertEquals(0x04, sr);
		assertEquals(0x32, pc);
		cpu.setSR(sr);
		assertFalse(cpu.isSupervisorMode());
		assertEquals(0x0100, cpu.getUSP().value);
		assertEquals(0x0100, cpu.getAddrRegisterLong(7).value);
		assertEquals(0x0200, cpu.getSSP().value);
	}
}
