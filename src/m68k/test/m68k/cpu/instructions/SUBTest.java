package m68k.cpu.instructions;

/**
 * ${FILE}
 * <p>
 * Federico Berti
 * <p>
 * Copyright 2018
 * <p>
 */

import junit.framework.TestCase;
import m68k.cpu.Cpu;
import m68k.cpu.MC68000;
import m68k.memory.AddressSpace;
import m68k.memory.MemorySpace;
import m68k.TaintedValue;

public class SUBTest extends TestCase {
    AddressSpace bus;
    Cpu cpu;

    public void setUp() {
        bus = new MemorySpace(1);    //create 1kb of memory for the cpu
        cpu = new MC68000();
        cpu.setAddressSpace(bus);
        cpu.reset();
        cpu.setAddrRegisterLong(7, new TaintedValue(0x200,0));
    }

    public void testSUB_byte_zeroFlag() {
        bus.writeWord(4, new TaintedValue(0x9402,0));    // sub.b d2,d2
        testSUB_byte_zeroFlag(cpu, true, 0xFFFF_FF80, 0xFFFF_FF00);
    }

    public void testSUBQ_byte_zeroFlag() {
        bus.writeWord(4, new TaintedValue(0x5502,0));    // subi.b #2,d2
//        bus.writeWord(6, 2);
        testSUB_byte_zeroFlag(cpu, true, 0x0001_0102, 0x0001_0100);
    }

    public void testSUBI_byte_zeroFlag() {
        bus.writeWord(4, new TaintedValue(0x0402,0));    // subi.b #2,d2
        bus.writeWord(6, new TaintedValue(2,0));
        testSUB_byte_zeroFlag(cpu, true, 0x0001_0102, 0x0001_0100);
    }

    private void testSUB_byte_zeroFlag(Cpu cpu, boolean expectedZFlag, long d2_pre, long d2_post) {
        cpu.setPC(new TaintedValue(4,0));
        cpu.setDataRegisterLong(2, new TaintedValue((int) d2_pre,0));
        cpu.execute();
        assertEquals(d2_post, cpu.getDataRegisterLong(2).value);
        assertEquals(0x00, cpu.getDataRegisterByte(2).value);
        assertEquals(expectedZFlag, cpu.isFlagSet(Cpu.Z_FLAG));
    }
}
