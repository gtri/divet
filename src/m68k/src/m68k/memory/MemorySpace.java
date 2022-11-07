package m68k.memory;

import java.nio.ByteBuffer;
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
public class MemorySpace implements AddressSpace
{
	private ByteBuffer buffer;
	private int size;

	public MemorySpace(int sizeKb)
	{
		size = sizeKb * 1024;
		buffer = ByteBuffer.allocateDirect(size);
	}

	public void reset()
	{
	}

	public int getStartAddress()
	{
		return 0;
	}

	public int getEndAddress()
	{
		return size;
	}

	public TaintedValue readByte(int addr)
	{
		int v = buffer.get(addr);
		return new TaintedValue(v & 0x00ff,0);
	}

	public TaintedValue readWord(int addr)
	{
		int v =  buffer.getShort(addr);
		return new TaintedValue(v & 0x0000ffff,0);
	}

	public TaintedValue readLong(int addr)
	{
		return new TaintedValue(buffer.getInt(addr),0);
	}

	public void writeByte(int addr, TaintedValue value)
	{
		buffer.put(addr, (byte)(value.value & 0x00ff));
	}

	public void writeWord(int addr, TaintedValue value)
	{
		buffer.putShort(addr, (short)(value.value & 0x0000ffff));
	}

	public void writeLong(int addr, TaintedValue value)
	{
		buffer.putInt(addr, value.value);
	}

	public TaintedValue internalReadByte(int addr)
	{
		return readByte(addr);
	}

	public TaintedValue internalReadWord(int addr)
	{
		return readWord(addr);
	}

	public TaintedValue internalReadLong(int addr)
	{
		return readLong(addr);
	}

	public void internalWriteByte(int addr, TaintedValue value)
	{
		writeByte(addr, value);
	}

	public void internalWriteWord(int addr, TaintedValue value)
	{
		writeWord(addr, value);
	}

	public void internalWriteLong(int addr, TaintedValue value)
	{
		writeLong(addr, value);
	}

	public int size()
	{
		return size;
	}
}
