package m68k.cpu.instructions;

import junit.framework.TestCase;
import m68k.cpu.Cpu;
import m68k.cpu.MC68000;
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
public class ADDTest extends TestCase
{
	AddressSpace bus;
	Cpu cpu;

	public void setUp()
	{
		bus = new MemorySpace(1);	//create 1kb of memory for the cpu
		cpu = new MC68000();
		cpu.setAddressSpace(bus);
		cpu.reset();
		cpu.setAddrRegisterLong(7, new TaintedValue(0x200,0));
	}

	public void testADD()
	{
		cpu.setPC(new TaintedValue(4,0));
		cpu.setDataRegisterByte(0, new TaintedValue(0x40,0));
		cpu.setDataRegisterByte(1, new TaintedValue(0x80,0));
		bus.writeWord(4, new TaintedValue(0xd001,0));	// add.b d1,d0
		int ticks = cpu.execute();
		assertEquals(6, cpu.getPC().value);
		assertEquals(0xc0, cpu.getDataRegisterByte(0).value);
		assertEquals(0x80, cpu.getDataRegisterByte(1).value);
		assertEquals(4, ticks);
		assertFalse(cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.Z_FLAG));
		assertTrue(cpu.isFlagSet(Cpu.N_FLAG));
		assertFalse(cpu.isFlagSet(Cpu.X_FLAG));

		cpu.setPC(new TaintedValue(4,0));
		cpu.setDataRegisterWord(0, new TaintedValue(0x8000,0));
		cpu.setDataRegisterWord(1, new TaintedValue(0x8500,0));
		bus.writeWord(4, new TaintedValue(0xd041,0));	// add.w d1,d0
		ticks = cpu.execute();
		assertEquals(6, cpu.getPC().value);
		assertEquals("d0", 0x0500, cpu.getDataRegisterWord(0).value);
		assertEquals("d1", 0x8500, cpu.getDataRegisterWord(1).value);
		assertEquals(4, ticks);
		assertTrue("c-flag", cpu.isFlagSet(Cpu.C_FLAG));
		assertTrue("v-flag", cpu.isFlagSet(Cpu.V_FLAG));
		assertFalse("z-flag", cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse("n-flag", cpu.isFlagSet(Cpu.N_FLAG));
		assertTrue("x-flag", cpu.isFlagSet(Cpu.X_FLAG));


		cpu.setPC(new TaintedValue(4,0));
		cpu.setDataRegisterLong(0, new TaintedValue(0xfffffffc,0));
		cpu.setDataRegisterLong(1, new TaintedValue(0x04,0));
		bus.writeWord(4, new TaintedValue(0xd081,0));	// add.l d1,d0
		ticks = cpu.execute();
		assertEquals(6, cpu.getPC().value);
		assertEquals("d0", 0, cpu.getDataRegisterLong(0).value);
		assertEquals("d1", 0x04, cpu.getDataRegisterWord(1).value);
		assertEquals(6, ticks);
		assertTrue("c-flag", cpu.isFlagSet(Cpu.C_FLAG));
		assertFalse("v-flag", cpu.isFlagSet(Cpu.V_FLAG));
		assertTrue("z-flag", cpu.isFlagSet(Cpu.Z_FLAG));
		assertFalse("n-flag", cpu.isFlagSet(Cpu.N_FLAG));
		assertTrue("x-flag", cpu.isFlagSet(Cpu.X_FLAG));
	}
}
