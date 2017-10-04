
package rlwe;

/**************************************************************************************************
 *
 * Implements elements over finite field GF(q) for use in RLWE implementation. The primality of q
 * is not checked because Fq need not be a valid field for the algorithm to work. In particular the 
 * BCNS implementation uses q = 2^32 - 1 which is not prime. This implementation does not check 
 * whether q is small enough to fit into an int.
 *  
 **************************************************************************************************/

import java.util.Arrays;
import java.lang.System;
import java.lang.Math;
import java.nio.ByteBuffer;


class Felm {

  private static int q = 2;                   // set q to a placeholder until it has been set
  private static int numbits = 1;             // maximum number of bits in an Felm (depends on q)
  private int value;

  public static final Felm ZERO = new Felm (0);
  public static final Felm ONE = new Felm (1);


  public Felm () {
    value = 0;
  }

  public Felm (int v) {
    value = (v % q + q) % q;                  // ensure value is positive even if v is negative
  }


  public Felm (Felm a) {
    value = a.fqGetValue();
  }


  public static void setModulus (int qIn) {
    q = qIn;
    numbits = Integer.SIZE - Integer.numberOfLeadingZeros (q-1);
  }


  public static int getModulus () {
    return q;
  }


  public int fqGetValue () {
    return value;
  }


  public void fqSetValue (int v) {
    value = v;
  }


  public Felm fqAdd (Felm y) {
    return new Felm (value + y.value);
  }


  public Felm fqSub (Felm y) {
    return new Felm (value - y.value);
  }


  public Felm fqMult (Felm y) {
    return new Felm (value * y.value);
  }


  public Felm fqSqr () {
    return new Felm ((int) Math.pow(value, 2));
  }


  public Felm fqPow (int exponent) {
    Felm result = new Felm (1);

    for (int i = exponent; i > 0; i--)
      result = fqMult (result);

    return result;
  }

  
  public boolean fqIsZero() {
    return value == 0;
  }


  public boolean fqIsEven() {
    return (value & 1) == 0;
  }


  public boolean fqIsOdd() {
    return (value & 1) == 1;
  }


  public boolean fqEqual (Felm y) {
    return value == y.value;
  }


  public boolean fqLessThan (Felm y) {
    return value < y.value;
  }


  public boolean fqGreaterThan (Felm y) {
    return value > y.value;
  }


  public Felm fqNegate() {
    return new Felm (q - value);
  }


  // Uses extended Euclidean algorithm
  public Felm fqInverse() {
    int a = value, m = q, x = 0, y = 1, quotient, tempy, tempa;

    while (a != 0) {
      quotient = m / a;
      tempy = y;
      y = x - quotient * y;
      x = tempy;
      tempa = a;
      a = m - quotient * a;
      m = tempa;
    }
    
    return new Felm (x);
  }


  public Felm fqDiv (Felm d) {
    Felm dinv = d.fqInverse();
    return fqMult (dinv);
  }


  public Felm rShift (int sb) {
    return new Felm (value >> sb);
  }


  public int getBit (int pos) {
    return value & (1 << pos);
  }


  public String toString() {
    return "0x" + String.format ("%04x", value);
  }


  public byte[] toByteArray() {
    return ByteBuffer.allocate(Integer.SIZE).putInt(value).array(); 
  }
}

