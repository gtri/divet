/*
 * Java ARM-emu.
 * 
 * (C) Copyright 2011-2012, J.W. Janssen <j.w.janssen@lxtreme.nl>
 */
package armcore;


import java.util.*;


/**
 * Denotes a memory map, containing various chunks of data.
 */
public interface Memory
{
  /**
   * Reads a 16-bit value from this memory at the given address.
   * 
   * @param aAddr
   *          the memory location to read.
   * @return the 16-bit value at the given memory location.
   */
  public short read16(int aAddr);

  /**
   * Reads a 32-bit value from this memory at the given address.
   * 
   * @param aAddr
   *          the memory location to read.
   * @return the 32-bit value at the given memory location.
   */
  public int read32(int aAddr);

  /**
   * Reads a 8-bit value from this memory at the given address.
   * 
   * @param aAddr
   *          the memory location to read.
   * @return the 8-bit value at the given memory location.
   */
  public byte read8(int aAddr);

  /**
   * Writes a 16-bit value to the memory denoted by the given address.
   * 
   * @param aAddr
   *          the memory location to write;
   * @param aValue
   *          the 16-bit value to write.
   */
  public void write16(int aAddr, short aValue);

  /**
   * Writes a 32-bit value to the memory denoted by the given address.
   * 
   * @param aAddr
   *          the memory location to write;
   * @param aValue
   *          the 32-bit value to write.
   */
  public void write32(int aAddr, int aValue);

  /**
   * Writes a 8-bit value to the memory denoted by the given address.
   * 
   * @param aAddr
   *          the memory location to write;
   * @param aValue
   *          the 8-bit value to write.
   */
  public void write8(int aAddr, byte aValue);

}
