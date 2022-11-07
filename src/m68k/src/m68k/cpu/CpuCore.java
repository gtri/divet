package m68k.cpu;

import m68k.memory.AddressSpace;
import m68k.TaintedValue;
import java.nio.ByteBuffer;

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
public abstract class CpuCore implements Cpu
{
	protected AddressSpace memory;
	protected TaintedValue[] data_regs;
	protected TaintedValue[] addr_regs;
	protected TaintedValue reg_pc;
	protected int reg_sr;
	protected TaintedValue reg_usp;
	protected TaintedValue reg_ssp;
	protected Operand[] srcHandlers;
	protected Operand[] dstHandlers;
	protected Operand srcEAHandler;
	protected Operand dstEAHandler;
	protected int currentInstructionAddress;
	protected StringBuilder disasmBuffer;

	public CpuCore()
	{
		data_regs = new TaintedValue[8];
		addr_regs = new TaintedValue[8];
		for( int i=0; i<8; i++ ) {
			data_regs[i] = new TaintedValue(0,0);
			addr_regs[i] = new TaintedValue(0,0);
		}
		reg_pc = new TaintedValue(0,0);
		reg_usp = new TaintedValue(0,0);
		reg_ssp = new TaintedValue(0,0);

		srcEAHandler = null;
		dstEAHandler = null;

		memory = null;

		disasmBuffer = new StringBuilder(64);
		initEAHandlers();
	}

	public ByteBuffer getState() {
		ByteBuffer state = ByteBuffer.allocate(144);
		state.putInt(data_regs[0].value);
		state.putInt(data_regs[0].tainted);
		state.putInt(data_regs[1].value);
		state.putInt(data_regs[1].tainted);
		state.putInt(data_regs[2].value);
		state.putInt(data_regs[2].tainted);
		state.putInt(data_regs[3].value);
		state.putInt(data_regs[3].tainted);
		state.putInt(data_regs[4].value);
		state.putInt(data_regs[4].tainted);
		state.putInt(data_regs[5].value);
		state.putInt(data_regs[5].tainted);
		state.putInt(data_regs[6].value);
		state.putInt(data_regs[6].tainted);
		state.putInt(data_regs[7].value);
		state.putInt(data_regs[7].tainted);
		state.putInt(addr_regs[0].value);
		state.putInt(addr_regs[0].tainted);
		state.putInt(addr_regs[1].value);
		state.putInt(addr_regs[1].tainted);
		state.putInt(addr_regs[2].value);
		state.putInt(addr_regs[2].tainted);
		state.putInt(addr_regs[3].value);
		state.putInt(addr_regs[3].tainted);
		state.putInt(addr_regs[4].value);
		state.putInt(addr_regs[4].tainted);
		state.putInt(addr_regs[5].value);
		state.putInt(addr_regs[5].tainted);
		state.putInt(addr_regs[6].value);
		state.putInt(addr_regs[6].tainted);
		state.putInt(addr_regs[7].value);
		state.putInt(addr_regs[7].tainted);
		state.putInt(reg_usp.value);
		state.putInt(reg_ssp.value);
		state.putInt(reg_pc.value);
		state.putInt(reg_sr);
		state.rewind();
		return state;
	}
	
	public void setState(ByteBuffer state) {
		data_regs[0].value = state.getInt();
		data_regs[0].tainted = state.getInt();
		data_regs[1].value = state.getInt();
		data_regs[1].tainted = state.getInt();
		data_regs[2].value = state.getInt();
		data_regs[2].tainted = state.getInt();
		data_regs[3].value = state.getInt();
		data_regs[3].tainted = state.getInt();
		data_regs[4].value = state.getInt();
		data_regs[4].tainted = state.getInt();
		data_regs[5].value = state.getInt();
		data_regs[5].tainted = state.getInt();
		data_regs[6].value = state.getInt();
		data_regs[6].tainted = state.getInt();
		data_regs[7].value = state.getInt();
		data_regs[7].tainted = state.getInt();
		addr_regs[0].value = state.getInt();
		addr_regs[0].tainted = state.getInt();
		addr_regs[1].value = state.getInt();
		addr_regs[1].tainted = state.getInt();
		addr_regs[2].value = state.getInt();
		addr_regs[2].tainted = state.getInt();
		addr_regs[3].value = state.getInt();
		addr_regs[3].tainted = state.getInt();
		addr_regs[4].value = state.getInt();
		addr_regs[4].tainted = state.getInt();
		addr_regs[5].value = state.getInt();
		addr_regs[5].tainted = state.getInt();
		addr_regs[6].value = state.getInt();
		addr_regs[6].tainted = state.getInt();
		addr_regs[7].value = state.getInt();
		addr_regs[7].tainted = state.getInt();
		reg_usp.value = state.getInt();
		reg_ssp.value = state.getInt();
		reg_pc.value = state.getInt();
		reg_sr = state.getInt();
	}

	public void setAddressSpace(AddressSpace as)
	{
		this.memory = as;
	}

	public void reset()
	{
		//NOTE: called during initialization
		reg_ssp = memory.readLong(0);
		addr_regs[7] = new TaintedValue(reg_ssp);
		reg_pc = memory.readLong(4);
		//supervisor mode, interrupts enabled
		reg_sr = 0x2700;
	}

	@Override
	public void resetExternal() {
		//NOTE: this has to be sent to all external devices - called by RESET instruction
	}

	public void stop()
	{
		//TODO: called by STOP instruction - should halt cpu and wait for interrupt
	}

	public TaintedValue getDataRegisterByte(int reg)
	{
		return new TaintedValue(data_regs[reg].value & 0x00ff, data_regs[reg].tainted);
	}
	public TaintedValue getDataRegisterByteSigned(int reg)
	{
		return new TaintedValue(signExtendByte(data_regs[reg].value), data_regs[reg].tainted);
	}
	public TaintedValue getDataRegisterWord(int reg)
	{
		return new TaintedValue(data_regs[reg].value & 0x0000ffff, data_regs[reg].tainted);
	}
	public TaintedValue getDataRegisterWordSigned(int reg)
	{
		return new TaintedValue(signExtendWord(data_regs[reg].value), data_regs[reg].tainted);
	}
	public TaintedValue getDataRegisterLong(int reg)
	{
		return new TaintedValue(data_regs[reg]);
	}
	public void setDataRegisterByte(int reg, TaintedValue value)
	{
		data_regs[reg] = new TaintedValue( (data_regs[reg].value & 0xffffff00) | (value.value & 0x00ff), data_regs[reg].tainted | value.tainted);
	}
	public void setDataRegisterWord(int reg, TaintedValue value)
	{
		data_regs[reg] = new TaintedValue( (data_regs[reg].value & 0xffff0000) | (value.value & 0x0000ffff), data_regs[reg].tainted | value.tainted);
	}
	public void setDataRegisterLong(int reg, TaintedValue value)
	{
		data_regs[reg] = new TaintedValue(value);
	}
	// address registers
	public TaintedValue getAddrRegisterByte(int reg)
	{
		return new TaintedValue( addr_regs[reg].value & 0x00ff, addr_regs[reg].tainted);
	}
	public TaintedValue getAddrRegisterByteSigned(int reg)
	{
		return new TaintedValue(signExtendByte(addr_regs[reg].value), addr_regs[reg].tainted);
	}
	public TaintedValue getAddrRegisterWord(int reg)
	{
		return new TaintedValue(addr_regs[reg].value & 0x0000ffff, addr_regs[reg].tainted);
	}
	public TaintedValue getAddrRegisterWordSigned(int reg)
	{
		return new TaintedValue(signExtendWord(addr_regs[reg].value), addr_regs[reg].tainted);
	}
	public TaintedValue getAddrRegisterLong(int reg)
	{
		return new TaintedValue(addr_regs[reg]);
	}

	public void setAddrRegisterByte(int reg, TaintedValue value)
	{
		addr_regs[reg] = new TaintedValue((addr_regs[reg].value & 0xffffff00) | (value.value & 0x00ff), addr_regs[reg].tainted | value.tainted);
		if(reg == 7)
		{
			if(isSupervisorMode())
			{
				reg_ssp = new TaintedValue(addr_regs[reg]);
			}
			else
			{
				reg_usp = new TaintedValue(addr_regs[reg]);
			}
		}
	}
	public void setAddrRegisterWord(int reg, TaintedValue value)
	{
		addr_regs[reg] = new TaintedValue((addr_regs[reg].value & 0xffff0000) | (value.value & 0x0000ffff), addr_regs[reg].tainted | value.tainted);
		if(reg == 7)
		{
			if(isSupervisorMode())
			{
				reg_ssp = new TaintedValue(addr_regs[reg]);
			}
			else
			{
				reg_usp = new TaintedValue(addr_regs[reg]);
			}
		}
	}
	public void setAddrRegisterLong(int reg, TaintedValue value)
	{
		addr_regs[reg] = new TaintedValue(value);
		if(reg == 7)
		{
			if(isSupervisorMode())
			{
				reg_ssp = new TaintedValue(value);
			}
			else
			{
				reg_usp = new TaintedValue(value);
			}
		}
	}

	public TaintedValue getPC()
	{
		return new TaintedValue(reg_pc);
	}

	public void setPC(TaintedValue address)
	{
		reg_pc = new TaintedValue(address);
	}

	// pc fetches - for reading data following instructions and incrementing the PC afterwards
	public TaintedValue fetchPCWord()
	{
		TaintedValue value = readMemoryWord(reg_pc.value);
		reg_pc.value += 2;
		return value;
	}

	public TaintedValue fetchPCWordSigned()
	{
		TaintedValue value = readMemoryWordSigned(reg_pc.value);
		reg_pc.value += 2;
		return value;
	}

	public TaintedValue fetchPCLong()
	{
		TaintedValue value = readMemoryLong(reg_pc.value);
		reg_pc.value += 4;
		return value;
	}

	// status reg
	public int getCCRegister()
	{
		return reg_sr & 0x00ff;
	}

	public int getSR()
	{
		return reg_sr;
	}

	public void setCCRegister(int value)
	{
		reg_sr = (reg_sr & 0xff00) | (value & 0x00ff);
	}

	public void setSR(int value)
	{
		//check for supervisor bit change
		if(((reg_sr & SUPERVISOR_FLAG) ^ (value & SUPERVISOR_FLAG)) != 0)
		{
			//if changing via this method don't push/pop sr and pc - this is only called by andi/eori/ori

			if((value & SUPERVISOR_FLAG) != 0)
			{
				reg_usp = new TaintedValue(addr_regs[7]);
				addr_regs[7] = new TaintedValue(reg_ssp);
			}
			else
			{
				//switch stacks
				reg_ssp = new TaintedValue(addr_regs[7]);
				addr_regs[7] = new TaintedValue(reg_usp);
			}
		}
		reg_sr = value;
	}

	/**
	 * Set the SR when coming from an RTE.
	 * We might already have been IN supervisor mode when the exception was caused (eg a Trap called in supervisor mode),
	 * so we must check the S bit we get back from the stack and possibly STAY in supervisor mode even after the RTE.
	 * @param value
	 */
	public void setSR2(int value)
	{
		// old value of SR, this will be in supermode
		reg_sr = value;							// new value of SR, could be user mode or super mode
		if ((reg_sr & SUPERVISOR_FLAG) == 0)	// we changed back to user mode,change stack pointer
		{
			reg_ssp = new TaintedValue(addr_regs[7]);				// keep supervisor stack pointer
			addr_regs[7] = new TaintedValue(reg_usp) ;			// get user stack pointer
		}
	}

	public void setFlags(int flags)
	{
		//only set CC flags so clear top byte
		reg_sr |= (flags & 0x00ff);
	}

	public void clrFlags(int flags)
	{
		//we need to invert the flags and then AND them with the SR to clear
		reg_sr &= ~(flags & 0x00ff);
	}

	public boolean isFlagSet(int flag)
	{
		return ((reg_sr & flag) == flag);
	}

	public void calcFlags(InstructionType type, int src, int dst, int result, Size sz)
	{
		calcFlagsParam(type, src, dst, result, 0, sz);
	}

	public void calcFlagsParam(InstructionType type, int src, int dst, int result, int extraParam, Size sz)
	{
		boolean Sm = (src & sz.msb()) != 0;
		boolean Dm = (dst & sz.msb()) != 0;
		boolean Rm = (result & sz.msb()) != 0;

		switch(type)
		{
			case ADD:	//ADD, ADDI, ADDQ
			{
				boolean Zm = (result & sz.mask()) == 0;
				if((Sm && Dm && !Rm) || (!Sm && !Dm && Rm))
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if((Sm && Dm) || (!Rm && Dm) || (Sm && !Rm))
				{
					reg_sr |= (C_FLAG | X_FLAG);
				}
				else
				{
					reg_sr &= ~(C_FLAG | X_FLAG);
				}

				if(Zm)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}

			case ADDX:
			{
				if((Sm && Dm && !Rm) || (!Sm && !Dm && Rm))
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if((Sm && Dm) || (!Rm && Dm) || (Sm && !Rm))
				{
					reg_sr |= (C_FLAG | X_FLAG);
				}
				else
				{
					reg_sr &= ~(C_FLAG | X_FLAG);
				}

				if(result != 0)
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}

			case ASL:
			{
				//params are different here!
				if(src != 0)	// shift count
				{
					if(dst != 0)	// last bit out
					{
						reg_sr |= (C_FLAG | X_FLAG);
					}
					else
					{
						reg_sr &= ~(C_FLAG | X_FLAG);
					}
				}

				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}

				if(extraParam != 0)	// msb changed
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~V_FLAG;
				}

				break;
			}

			case ASR:
			{
				//params are different here!
				if(src != 0)	// shift count
				{
					if(dst != 0)	// last bit out
					{
						reg_sr |= (C_FLAG | X_FLAG);
					}
					else
					{
						reg_sr &= ~(C_FLAG | X_FLAG);
					}
				}

				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}

				// always cleared
				reg_sr &= ~V_FLAG;

				break;
			}

			case CMP:	// CMP, CMPA, CMPI CMPM
			{
				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if((!Sm && Dm && !Rm) || (Sm && !Dm && Rm))
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if((Sm && !Dm) || (Rm && !Dm) || (Sm && Rm))
				{
					reg_sr |= C_FLAG;
				}
				else
				{
					reg_sr &= ~(C_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}
			case LSL:
			case LSR:
			case ROXL:
			case ROXR:
			{
				if(src > 0)	//shift count
				{
					if(dst != 0)	//last bit out
					{
						reg_sr |= (C_FLAG | X_FLAG);
					}
					else
					{
						reg_sr &= ~(C_FLAG | X_FLAG);
					}
				}

				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}

				reg_sr &= ~(V_FLAG);

				break;
			}
			case AND:
			case EOR:
			case MOVE:
			case NOT:
			case OR:
			{
				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}

				reg_sr &= ~(V_FLAG | C_FLAG);
				break;
			}
			case NEG:
			{
				if(Sm && Rm)
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if(result == 0)
				{
					reg_sr |= Z_FLAG;
					reg_sr &= ~(X_FLAG | C_FLAG);
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
					reg_sr |= (X_FLAG | C_FLAG);
				}
				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}
			case NEGX:
			{
				if(Sm && Rm)
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}
				if(Sm || Rm)
				{
					reg_sr |= (X_FLAG | C_FLAG);
				}
				else
				{
					reg_sr &= ~(X_FLAG | C_FLAG);
				}
				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}
				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}
			case ROL:
			case ROR:
			{
				if(src > 0)	//shift count
				{
					if(dst != 0)	//last bit out
					{
						reg_sr |= C_FLAG;
					}
					else
					{
						reg_sr &= ~(C_FLAG);
					}
				}

				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}

				reg_sr &= ~(V_FLAG);

				break;
			}

			case SUB:
			{
				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if((!Sm && Dm && !Rm) || (Sm && !Dm && Rm))
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if((Sm && !Dm) || (Rm && !Dm) || (Sm && Rm))
				{
					reg_sr |= (C_FLAG | X_FLAG);
				}
				else
				{
					reg_sr &= ~(C_FLAG | X_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}

			case SUBX:
			{
				if(result != 0)
				{
					reg_sr &= ~(Z_FLAG);
				}

				if((!Sm && Dm && !Rm) || (Sm && !Dm && Rm))
				{
					reg_sr |= V_FLAG;
				}
				else
				{
					reg_sr &= ~(V_FLAG);
				}

				if((Sm && !Dm) || (Rm && !Dm) || (Sm && Rm))
				{
					reg_sr |= (C_FLAG | X_FLAG);
				}
				else
				{
					reg_sr &= ~(C_FLAG | X_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				break;
			}
                            
			// swap also affects the SR
			case SWAP:
			{
				if(result == 0)
				{
					reg_sr |= Z_FLAG;
				}
				else
				{
					reg_sr &= ~(Z_FLAG);
				}

				if(Rm)
				{
					reg_sr |= N_FLAG;
				}
				else
				{
					reg_sr &= ~(N_FLAG);
				}
				reg_sr &= ~(V_FLAG);            // these are always set to 0
				reg_sr &= ~(C_FLAG);
				break;
			}
			default:
			{
				throw new IllegalArgumentException("No flags handled for " + type);
			}
		}
	}

	public boolean testCC(int cc)
	{
		int ccr = reg_sr & 0x001f;

		switch(cc)
		{
			case 0:		// T
			{
				return true;
			}
			case 1:		// F
			{
				return false;
			}
			case 2:		//HI:
			{
				return ((ccr & (C_FLAG | Z_FLAG)) == 0);
			}
			case 3:		//LS:
			{
				return ((ccr & (C_FLAG | Z_FLAG)) != 0);
			}
			case 4:		//CC:
			{
				return ((ccr & C_FLAG) == 0);
			}
			case 5:		//CS:
			{
				return ((ccr & C_FLAG) != 0);
			}
			case 6:		//NE:
			{
				return ((ccr & Z_FLAG) == 0);
			}
			case 7:		//EQ:
			{
				return ((ccr & Z_FLAG) != 0);
			}
			case 8:		//VC:
			{
				return ((ccr & V_FLAG) == 0);
			}
			case 9:		//VS:
			{
				return ((ccr & V_FLAG) != 0);
			}
			case 10:	//PL:
			{
				return ((ccr & N_FLAG) == 0);
			}
			case 11:	//MI:
			{
				return ((ccr & N_FLAG) != 0);
			}
			case 12:	//GE:
			{
				int v = ccr & (N_FLAG | V_FLAG);
				return (v == 0 || v == (N_FLAG | V_FLAG));
			}
			case 13:	//LT:
			{
				int v = ccr & (N_FLAG | V_FLAG);
				return (v == N_FLAG || v == V_FLAG);
			}
			case 14:	//GT:
			{
				int v = ccr & (N_FLAG | V_FLAG | Z_FLAG);
				return (v == 0 || v == (N_FLAG | V_FLAG));
			}
			case 15:	//LE:
			{
				int v = ccr & (N_FLAG | V_FLAG | Z_FLAG);
				return ((v & Z_FLAG) != 0 || (v == N_FLAG) || (v == V_FLAG));
			}
		}
		throw new IllegalArgumentException("Invalid Condition Code value!");
	}

	public boolean isSupervisorMode()
	{
		return (reg_sr & SUPERVISOR_FLAG) == SUPERVISOR_FLAG;
	}

	public void pushWord(TaintedValue value)
	{
		// do we need to keep the usp or ssp up to date ?
		addr_regs[7].value -= 2;
		writeMemoryWord(addr_regs[7].value, value);
	}

	public void pushLong(TaintedValue value)
	{
		// do we need to keep the usp or ssp up to date ?
		addr_regs[7].value -= 4;
		writeMemoryLong(addr_regs[7].value, value);
	}

	public TaintedValue popWord()
	{
		// do we need to keep the usp or ssp up to date ?
		TaintedValue val = readMemoryWord(addr_regs[7].value);
		addr_regs[7].value += 2;
		return val;
	}

	public TaintedValue popLong()
	{
		// do we need to keep the usp or ssp up to date ?
		TaintedValue val = readMemoryLong(addr_regs[7].value);
		addr_regs[7].value += 4;
		return val;
	}

	public TaintedValue getUSP()
	{
		return new TaintedValue(reg_usp);
	}

	public void setUSP(TaintedValue address)
	{
		reg_usp = new TaintedValue(address);
		if(!isSupervisorMode())
			addr_regs[7] = new TaintedValue(reg_usp);
	}

	public TaintedValue getSSP()
	{
		return new TaintedValue(reg_ssp);
	}

	public void setSSP(TaintedValue address)
	{
		reg_ssp = new TaintedValue(address);

		if(isSupervisorMode())
			addr_regs[7] = new TaintedValue(reg_ssp);
	}

	public void setSupervisorMode(boolean enable)
	{
		if(enable)
		{
			int old_sr = reg_sr;
			if ((reg_sr & SUPERVISOR_FLAG) == 0) // were we in supervisor mode already?....
			{
				reg_sr |= SUPERVISOR_FLAG;      // ...no, so set supervisor bit
				reg_usp = new TaintedValue(addr_regs[7]);         // and change stack pointers
				addr_regs[7] = new TaintedValue(reg_ssp);
			}

			//save pc and status regs
			pushLong(reg_pc);
			pushWord(new TaintedValue(old_sr,0));
		}
		else
		{
			//switch back to user mode
			if((reg_sr & SUPERVISOR_FLAG) != 0)
			{
				//restore PC and status regs
				reg_sr = popWord().value;
				reg_pc = popLong();

				//switch stacks
				reg_ssp = new TaintedValue(addr_regs[7]);
				addr_regs[7] = new TaintedValue(reg_usp);
			}
		}
	}

	public void raiseException(int vector)
	{
		int address = (vector & 0x00ff) << 2;

		// don't call setSupervisorMode, do it directly
		int old_sr = reg_sr;	// SR BEFORE the exception

		if ((reg_sr & SUPERVISOR_FLAG) == 0)	// were we in supervisor mode already?....
		{
			reg_sr |= SUPERVISOR_FLAG;	// ...no, so set supervisor bit
			reg_usp = new TaintedValue(addr_regs[7]);		// and change stack pointers
			addr_regs[7] = new TaintedValue(reg_ssp);
		}

		//save pc and status regs
		pushLong(reg_pc);
		pushWord(new TaintedValue(old_sr,0));
		reg_sr &= ~(TRACE_FLAG);		// exceptions unset the trace flag

		TaintedValue xaddress = readMemoryLong(address);
		if(xaddress.value == 0)
		{
			//interrupt vector is uninitialised
			//raise a uninitialised interrupt vector exception instead
			//vector 15 == 0x003c
			xaddress = readMemoryLong(0x003c);
			//if this is zero as well the CPU should halt
			if(xaddress.value == 0)
			{
				throw new CpuException("Interrupt vector not set for uninitialised interrupt vector while trapping uninitialised vector " + vector);
			}
		}

		reg_pc = xaddress;
	}

	public void raiseSRException()
	{
		//always a privilege violation - vector 8
		int address = 32;

		//switch to supervisor mode
		int old_sr = reg_sr;

		if((reg_sr & SUPERVISOR_FLAG) == 0)
		{
			reg_sr |= SUPERVISOR_FLAG;	//set supervisor bit
			//switch stacks
			reg_usp = new TaintedValue(addr_regs[7]);
			addr_regs[7] = new TaintedValue(reg_ssp);
		}

		//subtly different in that the address of the instruction is pushed rather than the address of the next instruction
		//save pc and status regs - operands fetched in supervisor mode so PC at current address
		pushLong(new TaintedValue(currentInstructionAddress,0));
		pushWord(new TaintedValue(old_sr,0));

		//todo: handle special exception cases & build stack info

		TaintedValue xaddress = readMemoryLong(address);
		if(xaddress.value == 0)
		{
			//interrupt vector is uninitialised
			//raise a uninitialised interrupt vector exception instead
			//vector 15 == 0x003c
			xaddress = readMemoryLong(0x003c);
			//if this is zero as well the CPU should halt
			if(xaddress.value == 0)
			{
				throw new CpuException("Interrupt vector not set for uninitialised interrupt vector while trapping uninitialised vector 8");
			}
		}

		reg_pc = xaddress;
	}


	public int getInterruptLevel()
	{
		return (reg_sr >> 8) & 0x07;
	}

	protected void setInterruptLevel(int level)
	{
		reg_sr &= ~(INTERRUPT_FLAGS_MASK);
		reg_sr |= (level & 0x07) << 8;
	}

	public void raiseInterrupt(int priority)
	{
		if(priority == 0)
			return;

		priority &= 0x07;

		//is it higher than the current interrupt mask ?
    	if(priority >  getInterruptLevel())
		{
			//make it an autovectored interrupt
			raiseException(priority + 24);
			setInterruptLevel(priority);
		}
	}


	//memory interface
	public TaintedValue readMemoryByte(int addr)
	{
		return memory.readByte(addr);
	}
	public TaintedValue readMemoryByteSigned(int addr)
	{
		TaintedValue v = memory.readByte(addr);
		v.value = signExtendByte(v.value);
		return v;
	}
	public TaintedValue readMemoryWord(int addr)
	{
		return memory.readWord(addr);
	}
	public TaintedValue readMemoryWordSigned(int addr)
	{
		TaintedValue v = memory.readWord(addr);
		v.value = signExtendWord(v.value);
		return v;
	}
	public TaintedValue readMemoryLong(int addr)
	{
		return memory.readLong(addr);
	}
	public void writeMemoryByte(int addr, TaintedValue value)
	{
		memory.writeByte(addr, value);
	}
	public void writeMemoryWord(int addr, TaintedValue value)
	{
		memory.writeWord(addr, value);
	}
	public void writeMemoryLong(int addr, TaintedValue value)
	{
		memory.writeLong(addr, value);
	}

	public Operand resolveSrcEA(int mode, int reg, Size size)
	{
		if(mode < 7)
			srcEAHandler = srcHandlers[mode];
		else
			srcEAHandler = srcHandlers[mode + reg];

		srcEAHandler.init(reg, size);
		return srcEAHandler;
	}

	// destination EA
	public Operand resolveDstEA(int mode, int reg, Size size)
	{
		if(mode < 7)
			dstEAHandler = dstHandlers[mode];
		else
			dstEAHandler = dstHandlers[mode + reg];

		dstEAHandler.init(reg, size);
		return dstEAHandler;
	}

	public DisassembledOperand disassembleSrcEA(int address, int mode, int reg, Size sz)
	{
		return disassembleEA(address, mode, reg, sz, true);
	}

	public DisassembledOperand disassembleDstEA(int address, int mode, int reg, Size sz)
	{
		return disassembleEA(address, mode, reg, sz, false);
	}

	protected DisassembledOperand disassembleEA(int address, int mode, int reg, Size sz, boolean is_src)
	{
		int bytes_read = 0;
		int mem = 0;
		disasmBuffer.delete(0, disasmBuffer.length());

		switch(mode)
		{
			case 0:
			{
				disasmBuffer.append("d").append(reg);
				break;
			}
			case 1:
			{
				disasmBuffer.append("a").append(reg);
				break;
			}
			case 2:
			{
				disasmBuffer.append("(a").append(reg).append(")");
				break;
			}
			case 3:
			{
				disasmBuffer.append("(a").append(reg).append(")+");
				break;
			}
			case 4:
			{
				disasmBuffer.append("-(a").append(reg).append(")");
				break;
			}
			case 5:
			{
				mem = readMemoryWordSigned(address).value;
				disasmBuffer.append(String.format("$%04x",(short)mem)).append("(a").append(reg).append(")");
				bytes_read = 2;
				break;
			}
			case 6:
			{
				mem = readMemoryWord(address).value;
				int dis = signExtendByte(mem);
				disasmBuffer.append(String.format("$%02x",(byte)dis)).append("(a").append(reg).append(",");
				disasmBuffer.append(((mem & 0x8000) != 0 ? "a" : "d")).append((mem >> 12) & 0x07).append(((mem & 0x0800) != 0 ? ".l" : ".w")).append(")");
				bytes_read = 2;
				break;
			}
			case 7:
			{
				switch(reg)
				{
					case 0:
					{
						mem = readMemoryWord(address).value;
						disasmBuffer.append(String.format("$%04x", mem));
						bytes_read = 2;
						break;
					}
					case 1:
					{
						mem = readMemoryLong(address).value;
						disasmBuffer.append(String.format("$%08x", mem));
						bytes_read = 4;
						break;
					}
					case 2:
					{
						mem = readMemoryWordSigned(address).value;
						disasmBuffer.append(String.format("$%04x(pc)",(short)mem));
						bytes_read = 2;
						break;
					}
					case 3:
					{
						mem = readMemoryWord(address).value;
						int dis = signExtendByte(mem);
						disasmBuffer.append(String.format("$%02x(pc,", (byte)dis));
						disasmBuffer.append(((mem & 0x8000) != 0 ? "a" : "d")).append((mem >> 12) & 0x07).append(((mem & 0x0800) != 0 ? ".l" : ".w")).append(")");
						bytes_read = 2;
						break;
					}
					case 4:
					{
						if(is_src)
						{
							if(sz == Size.Long)
							{
								mem = readMemoryLong(address).value;
								bytes_read = 4;
								disasmBuffer.append(String.format("#$%08x", mem));
							}
							else
							{
								mem = readMemoryWord(address).value;
								bytes_read = 2;
								disasmBuffer.append(String.format("#$%04x", mem));

								if(sz == Size.Byte)
								{
									mem &= 0x00ff;
								}
							}
						}
						else
						{
							if(sz == Size.Byte)
							{
								disasmBuffer.append("ccr");
							}
							else
							{
								disasmBuffer.append("sr");
							}
						}
						break;
					}
					default:
					{
						throw new IllegalArgumentException("Invalid reg specified for mode 7: " + reg);
					}
				}
				break;
			}
			default:
			{
				throw new IllegalArgumentException("Invalid mode specified: " + mode);
			}
		}
		return new DisassembledOperand(disasmBuffer.toString(), bytes_read, mem);
	}

	//effective address handling
	public void incrementAddrRegister(int reg, int numBytes)
	{
		addr_regs[reg].value += numBytes;
	}
	public void decrementAddrRegister(int reg, int numBytes)
	{
		addr_regs[reg].value -= numBytes;
	}

	protected int signExtendByte(int value)
	{
		if((value & 0x80) == 0x80)
		{
			value |= 0xffffff00;
		}
		else
		{
			value &= 0x000000ff;
		}
		return value;
	}

	protected int signExtendWord(int value)
	{
		if((value & 0x8000) == 0x8000)
		{
			value |= 0xffff0000;
		}
		else
		{
			value &= 0x0000ffff;
		}
		return value;
	}

	protected void initEAHandlers()
	{
		srcHandlers = new Operand[12];
		dstHandlers = new Operand[12];

		srcHandlers[0] = new DataRegisterOperand();
		srcHandlers[1] = new AddressRegisterOperand();
		srcHandlers[2] = new AddressRegisterIndirectOperand();
		srcHandlers[3] = new AddressRegisterPostIncOperand();
		srcHandlers[4] = new AddressRegisterPreDecOperand();
		srcHandlers[5] = new AddressRegisterWithDisplacementOperand();
		srcHandlers[6] = new AddressRegisterWithIndexOperand();
		srcHandlers[7] = new AbsoluteShortOperand();
		srcHandlers[8] = new AbsoluteLongOperand();
		srcHandlers[9] = new PCWithDisplacementOperand();
		srcHandlers[10] = new PCWithIndexOperand();
		srcHandlers[11] = new ImmediateOperand();

		dstHandlers[0] = new DataRegisterOperand();
		dstHandlers[1] = new AddressRegisterOperand();
		dstHandlers[2] = new AddressRegisterIndirectOperand();
		dstHandlers[3] = new AddressRegisterPostIncOperand();
		dstHandlers[4] = new AddressRegisterPreDecOperand();
		dstHandlers[5] = new AddressRegisterWithDisplacementOperand();
		dstHandlers[6] = new AddressRegisterWithIndexOperand();
		dstHandlers[7] = new AbsoluteShortOperand();
		dstHandlers[8] = new AbsoluteLongOperand();
		dstHandlers[9] = new PCWithDisplacementOperand();
		dstHandlers[10] = new PCWithIndexOperand();
		dstHandlers[11] = new StatusRegisterOperand();
	}

	class DataRegisterOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected final int index = 0;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
		}

		public TaintedValue getByte()
		{
			return getDataRegisterByte(regNumber);
		}

		public TaintedValue getWord()
		{
			return getDataRegisterWord(regNumber);
		}

		public TaintedValue getLong()
		{
			return getDataRegisterLong(regNumber);
		}

		public TaintedValue getByteSigned()
		{
			return getDataRegisterByteSigned(regNumber);
		}

		public TaintedValue getWordSigned()
		{
			return getDataRegisterWordSigned(regNumber);
		}

		public void setByte(TaintedValue value)
		{
			setDataRegisterByte(regNumber, value);
		}

		public void setWord(TaintedValue value)
		{
			setDataRegisterWord(regNumber, value);
		}

		public void setLong(TaintedValue value)
		{
			setDataRegisterLong(regNumber, value);
		}

		public boolean isRegisterMode()
		{
			return true;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			// always zero
			return 0;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			throw new RuntimeException("Data Register has no computed address");
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(2).append("d").append(regNumber).toString();
		}
	}

	class AddressRegisterOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected final int index = 1;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
		}

		public TaintedValue getByte()
		{
			return getAddrRegisterByte(regNumber);
		}

		public TaintedValue getWord()
		{
			return getAddrRegisterWord(regNumber);
		}

		public TaintedValue getLong()
		{
			return getAddrRegisterLong(regNumber);
		}

		public TaintedValue getByteSigned()
		{
			return getAddrRegisterByteSigned(regNumber);
		}

		public TaintedValue getWordSigned()
		{
			return getAddrRegisterWordSigned(regNumber);
		}

		public void setByte(TaintedValue value)
		{
			setAddrRegisterByte(regNumber, value);
		}

		public void setWord(TaintedValue value)
		{
			setAddrRegisterWord(regNumber, value);
		}

		public void setLong(TaintedValue value)
		{
			setAddrRegisterLong(regNumber, value);
		}

		public boolean isRegisterMode()
		{
			return true;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			//always zero
			return 0;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			throw new RuntimeException("Address Register direct has no computed address");
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(2).append("a").append(regNumber).toString();
		}

	}

	class AddressRegisterIndirectOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected int address;
		protected final int index = 2;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
			address = getAddrRegisterLong(regNumber).value;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 8 : 4;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(4).append("(a").append(regNumber).append(")").toString();
		}
	}

	class AddressRegisterPostIncOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected int address;
		protected final int index = 3;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
			address = getAddrRegisterLong(regNumber).value;

			// in the 68008 At LEAST, moving bytes to the stack will change the stack pointer by 2, not 1
			if (param == 7 && size.byteCount() == 1)
				incrementAddrRegister(regNumber, 2);
			else
				incrementAddrRegister(regNumber, size.byteCount());
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 8 : 4;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(5).append("(a").append(regNumber).append(")+").toString();
		}
	}

	class AddressRegisterPreDecOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected int address;
		protected final int index = 4;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;

			// in the 68008 At LEAST, moving bytes to the stack will change the stack pointer by 2, not 1
			if (param == 7 && size.byteCount() == 1)
				decrementAddrRegister(regNumber, 2);
			else
				decrementAddrRegister(regNumber, size.byteCount());

			address = getAddrRegisterLong(regNumber).value;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isSR()
		{
			return false;
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 10 : 6;
		}

		// used for jmp and jsr, lea, movem
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(5).append("-(a").append(regNumber).append(")").toString();
		}
	}

	class AddressRegisterWithDisplacementOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected int address;
		protected int displacement;
		protected final int index = 5;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
			displacement = fetchPCWordSigned().value;
			address = getAddrRegisterLong(regNumber).value + displacement;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 12 : 8;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(10).append(String.format("$%x",displacement)).append("(a").append(regNumber).append(")").toString();
		}
	}

	class AddressRegisterWithIndexOperand implements Operand
	{
		protected int regNumber;
		protected Size size;
		protected int address;
		protected int displacement;
		protected int idxRegNumber;
		protected Size idxSize;
		protected boolean idxIsAddressReg;
		protected final int index = 6;

		public void init(int param, Size sz)
		{
			regNumber = param;
			size = sz;
			int ext = fetchPCWordSigned().value;
			displacement = signExtendByte(ext);
			idxRegNumber = (ext >> 12) & 0x07;
			idxSize = ((ext & 0x0800) == 0x0800 ? Size.Long : Size.Word);
			idxIsAddressReg = ((ext & 0x8000) == 0x8000);
			int idxVal;
			if(idxIsAddressReg)
			{
				if(idxSize == Size.Word)
				{
					idxVal = getAddrRegisterWordSigned(idxRegNumber).value;
				}
				else
				{
					idxVal = getAddrRegisterLong(idxRegNumber).value;
				}
			}
			else
			{
				if(idxSize == Size.Word)
				{
					idxVal = getDataRegisterWordSigned(idxRegNumber).value;
				}
				else
				{
					idxVal = getDataRegisterLong(idxRegNumber).value;
				}
			}
			address = getAddrRegisterLong(regNumber).value + displacement + idxVal;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isSR()
		{
			return false;
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 14 : 10;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			StringBuilder sb = new StringBuilder(20);
			sb.append(displacement).append("(a").append(regNumber).append(",");
			if(idxIsAddressReg)
			{
				sb.append("a");
			}
			else
			{
				sb.append("d");
			}
			sb.append(idxRegNumber).append(idxSize.ext()).append(")");
			return sb.toString();
		}
	}

	class AbsoluteShortOperand implements Operand
	{
		protected Size size;
		protected int address;
		protected final int index = 7;

		public void init(int param, Size sz)
		{
			//don't need the param
			size = sz;
			// yes it is sign extended (the high byte is discarded in 68000 addressing)
			address = fetchPCWordSigned().value;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 12 : 8;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(12).append("$").append(Integer.toHexString(address)).append(".w").toString();
		}
	}

	class AbsoluteLongOperand implements Operand
	{
		protected Size size;
		protected int address;
		protected final int index = 8;

		public void init(int param, Size sz)
		{
			//don't need the param
			size = sz;
			address = fetchPCLong().value;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 16 : 12;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(12).append("$").append(Integer.toHexString(address)).append(".l").toString();
		}
	}

	class PCWithDisplacementOperand implements Operand
	{
		protected Size size;
		protected int address;
		protected int displacement;
		protected final int index = 9;

		public void init(int param, Size sz)
		{
			// param not used
			size = sz;
			//the address of pc before displacement read is used
			address = getPC().value;
			displacement = fetchPCWordSigned().value;
			address += displacement;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 12 : 8;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(12).append(displacement).append("(pc)").toString();
		}
	}

	class PCWithIndexOperand implements Operand
	{
		protected Size size;
		protected int address;
		protected int displacement;
		protected int idxRegNumber;
		protected Size idxSize;
		protected boolean idxIsAddressReg;
		protected final int index = 10;

		public void init(int param, Size sz)
		{
			// param not used
			size = sz;
			// get pc before it's incremented by the fetch
			address = getPC().value;
			int ext = fetchPCWordSigned().value;
			displacement = signExtendByte(ext);
			idxRegNumber = (ext >> 12) & 0x07;
			idxSize = ((ext & 0x0800) == 0x0800 ? Size.Long : Size.Word);
			idxIsAddressReg = ((ext & 0x8000) == 0x8000);
			int idxVal;
			if(idxIsAddressReg)
			{
				if(idxSize == Size.Word)
				{
					idxVal = getAddrRegisterWordSigned(idxRegNumber).value;
				}
				else
				{
					idxVal = getAddrRegisterLong(idxRegNumber).value;
				}
			}
			else
			{
				if(idxSize == Size.Word)
				{
					idxVal = getDataRegisterWordSigned(idxRegNumber).value;
				}
				else
				{
					idxVal = getDataRegisterLong(idxRegNumber).value;
				}
			}
			address += displacement + idxVal;
		}

		public TaintedValue getByte()
		{
			return readMemoryByte(address);
		}

		public TaintedValue getWord()
		{
			return readMemoryWord(address);
		}

		public TaintedValue getLong()
		{
			return readMemoryLong(address);
		}

		public TaintedValue getByteSigned()
		{
			return readMemoryByteSigned(address);
		}

		public TaintedValue getWordSigned()
		{
			return readMemoryWordSigned(address);
		}

		public void setByte(TaintedValue value)
		{
			writeMemoryByte(address, value);
		}

		public void setWord(TaintedValue value)
		{
			writeMemoryWord(address, value);
		}

		public void setLong(TaintedValue value)
		{
			writeMemoryLong(address, value);
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 14 : 10;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			return address;
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			StringBuilder sb = new StringBuilder(20);
			sb.append(displacement).append("(pc,");
			if(idxIsAddressReg)
			{
				sb.append("a");
			}
			else
			{
				sb.append("d");
			}
			sb.append(idxRegNumber).append(idxSize.ext()).append(")");
			return sb.toString();
		}
	}

	class ImmediateOperand implements Operand
	{
		protected Size size;
		protected TaintedValue value;
		protected final int index = 11;

		public void init(int param, Size sz)
		{
			// param not used
			size = sz;
			if(size == Size.Long)
			{
				value = fetchPCLong();
			}
			else
			{
				// byte & word
				value = fetchPCWord();
				if(size == Size.Byte)
					value.value = value.value & 0x00ff;
			}
		}

		public TaintedValue getByte()
		{
			return new TaintedValue(value.value & 0x00ff,value.tainted);
		}

		public TaintedValue getWord()
		{
			return new TaintedValue(value.value & 0x0000ffff, value.tainted);
		}

		public TaintedValue getLong()
		{
			return value;
		}

		public TaintedValue getByteSigned()
		{
			return new TaintedValue(signExtendByte(value.value), value.tainted);
		}

		public TaintedValue getWordSigned()
		{
			return new TaintedValue(signExtendWord(value.value), value.tainted);
		}

		public void setByte(TaintedValue value)
		{
			// should never be called
			throw new RuntimeException("Cannot setByte on source only operand");
		}

		public void setWord(TaintedValue value)
		{
			// should never be called
			throw new RuntimeException("Cannot setWord on source only operand");
		}

		public void setLong(TaintedValue value)
		{
			// should never be called
			throw new RuntimeException("Cannot setLong on source only operand");
		}

		public boolean isRegisterMode()
		{
			return false;
		}

		public boolean isSR()
		{
			return false;
		}

		public int getTiming()
		{
			return size == Size.Long ? 12 : 8;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			throw new RuntimeException("Immediate addressing has no computed address");
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return new StringBuilder(12).append("#$").append(Integer.toHexString(value.value)).toString();
		}
	}

	class StatusRegisterOperand implements Operand
	{
		protected Size size;
		protected int value;
		protected String name;
		protected final int index = 12;

		public void init(int param, Size sz)
		{
			// param not used
			size = sz;
			switch(size)
			{
				case Byte:
				{
					//condition codes - not privileged
					value = getCCRegister();
					name = "ccr";
					break;
				}
				case Word:
				{
					//status register - priviledged!
					value = getSR();
					name = "sr";
					break;
				}
				default:
				{
					throw new IllegalArgumentException("Status Register is byte or word access only");
				}
			}
		}

		public TaintedValue getByte()
		{
			return new TaintedValue(value & 0x00ff, 0);
		}

		public TaintedValue getWord()
		{
			return new TaintedValue(value & 0x0000ffff, 0);
		}

		public TaintedValue getLong()
		{
			// should never be called
			throw new RuntimeException("Cannot getLong on status register");
		}

		public TaintedValue getByteSigned()
		{
			return new TaintedValue(signExtendByte(value), 0);
		}

		public TaintedValue getWordSigned()
		{
			return new TaintedValue(signExtendWord(value), 0);
		}

		public void setByte(TaintedValue value)
		{
			setCCRegister(value.value);
		}

		public void setWord(TaintedValue value)
		{
			setSR(value.value);
		}

		public void setLong(TaintedValue value)
		{
			// should never be called
			throw new RuntimeException("Cannot setLong on status register");
		}

		public boolean isRegisterMode()
		{
			return true;
		}

		public boolean isSR()
		{
			return true;
		}

		public int getTiming()
		{
			//no ea calc time
			return 0;
		}

		// used for jmp and jsr
		public int getComputedAddress()
		{
			throw new RuntimeException("Status Register has no computed address");
		}

		public int index()
		{
			return index;
		}

		public String toString()
		{
			return name;
		}
	}

}
