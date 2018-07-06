package rlwe;

/**************************************************************************************************
 *
 * Implements elements of a polynomial ring for the RLWE Key Exchange. To provide an optimized and
 * straight-forward implementation, the ring is fixed to be R = GF(12289) / (x^1024 - 1). The NTT 
 * optimizations included below are based on "Speeding up the Number Theoretic Transform for Faster 
 * Ideal Lattice-Based Cryptography" by Patrick Longa and Michael Naehrig.
 *
 * Note on endianness: coeff[i] is the coefficient on x^i. 
 *
 **************************************************************************************************/

import java.math.BigInteger;
import java.util.Arrays;
import java.lang.System;
import java.lang.Math;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;


class RingElt {
  static int ringEltLen = Constants.N;   
  static int modulus = Constants.Q;
  private long[] coeff;

  // Precomputed values to improve efficiency of number theoretic transforms
  private static long[] psiRev;     
  private static long[] omegaInvRev;   
  private static long nInvMultiplier;
  private static long omegaInvMultiplier;

  
  public RingElt () {
    coeff = new long[ringEltLen];
  }


  public RingElt (long[] coefficient) {
    int i, minLen;

    coeff = new long[ringEltLen];
    minLen = Math.min (ringEltLen, coefficient.length);

    for (i = 0; i < minLen; i++)
      coeff[i] = coefficient[i];
  } 


  public RingElt (RingElt b) {
    coeff = new long[ringEltLen];

    for (int i = 0; i < ringEltLen; i++)
      coeff[i] = b.getCoeff(i);    
  }


  public RingElt (byte[] inBytes) {
    int bytesPerCoeff = inBytes.length / ringEltLen;

    coeff = new long[ringEltLen];

    for (int i = 0; i < ringEltLen; i++) {
      for (int j = 0; j < bytesPerCoeff; j++)
	coeff[i] += (long) inBytes[i*bytesPerCoeff + j] << (8 * (bytesPerCoeff - j));
    }
  }


  public static void initialize () {
    psiRev = Constants.PSI_REV;
    omegaInvRev = Constants.OMEGA_INV_REV;
    nInvMultiplier = Constants.N_INV_MULTIPLIER;
    omegaInvMultiplier = Constants.OMEGA_INV_MULTIPLIER;
  }
  
  
  static int getLength () {
    return ringEltLen;
  }

  
  long getCoeff (int index) {
    if (index >= ringEltLen || index < 0)
      return 0;
    return coeff[index];
  }


  void setCoeff (int index, long value) {
    if (ringEltLen > index && index >= 0)
      coeff[index] = value;
  }


  long[] getCoeffs () {
    int i;
    long[] coeffcopy = new long[ringEltLen];

    for (i = 0; i < ringEltLen; i++)
      coeffcopy[i] = coeff[i];

    return coeffcopy;
  }
  

  static long reduce12289 (long a) {
    long c0, c1;

    c0 = a & 0xfff;
    c1 = a >> 12; 

    return 3*c0 - c1;
  }


  void twoReduce () {
    for (int i = 0; i < ringEltLen; i++) {
      coeff[i] = reduce12289 (coeff[i]);
      coeff[i] = reduce12289 (coeff[i]);
    }
  }
  

  RingElt ringAdd (RingElt a) {
    RingElt c = new RingElt ();
    long ci;
    
    for (int i = 0; i < ringEltLen; i++) {
      ci = coeff[i] + a.getCoeff(i);
      c.setCoeff (i, ci);
    }

    c.correction();
    return c;
  }


  RingElt pointwiseMult (RingElt a) {
    RingElt c = new RingElt ();
    long ci;
    
    for (int i = 0; i < ringEltLen; i++) {
      ci = reduce12289 (coeff[i] * a.getCoeff(i));
      ci = reduce12289 (ci);
      c.setCoeff (i, ci);
    }

    return c;
  }


  RingElt pointwiseMultAdd (RingElt a, RingElt b) {
    RingElt c = new RingElt ();
    long ci;

    for (int i = 0; i < ringEltLen; i++) {
      ci = reduce12289 (coeff[i] * a.getCoeff(i) + b.getCoeff(i));
      ci = reduce12289 (ci);
      c.setCoeff (i, ci);
    }

    return c;
  }


  void ntt () {
    int m, i, j, j1, j2, k = ringEltLen;
    long S, U, V;

    for (m = 1; m < ringEltLen; m = m << 1) {
      k = k >> 1;

      for (i = 0; i < m; i++) {
	j1 = i * k << 1;
	j2 = j1 + k - 1;
	S = psiRev[m + i];

	for (j = j1; j <= j2; j++) {
	  U = coeff[j];
	  V = reduce12289 (coeff[j + k] * S);
	  coeff[j] = U + V;
	  coeff[j + k] = U - V;	
	}
      }
    }

    for (i = 0; i < ringEltLen; i++)
      coeff[i] = reduce12289 (coeff[i]);
  }


  void nttInv () {
    int m, h, i, j, j1, j2, k = 1;
    long S, U, V, temp;

    for (m = ringEltLen; m > 2; m = m >> 1) {
      j1 = 0;
      h = m >> 1;

      for (i = 0; i < h; i++) {
	j2 = j1 + k - 1;
	S = omegaInvRev[h + i];

	for (j = j1; j <= j2; j++) {
	  U = coeff[j];
	  V = coeff[j + k];
	  coeff[j] = U + V;
	  coeff[j+k] = reduce12289 ((U - V) * S);
	}

	j1 = j1 + 2 * k;
      }

      k = k << 1;
    }
    
    for (j = 0; j < k; j++) {
      U = coeff[j];
      V = coeff[j + k];
      coeff[j] = reduce12289 ((U + V) * nInvMultiplier);
      coeff[j+k] = reduce12289 ((U - V) * omegaInvMultiplier);
    }

    twoReduce ();
    correction ();
  }


  public void correction () {
    int i;
    long mask;

    for (i = 0; i < ringEltLen; i++) {
      mask = coeff[i] >> 15;
      coeff[i] += (modulus & mask) - modulus;
      mask = coeff[i] >> 15;
      coeff[i] += (modulus & mask);
    }
  }


  public void multByConst (long c) {
    for (int i = 0; i < ringEltLen; i++) 
      coeff[i] = (coeff[i] * c) % modulus;
  }
  

  public void multBy3 () {
    // Assumes coefficients are positive and fully reduced
    long mask;
    
    for (int i = 0; i < ringEltLen; i++) {
      coeff[i] = (coeff[i] << 1) + coeff[i];
      
      mask = (modulus - coeff[i]) >> 15;
      coeff[i] = coeff[i] - (mask & modulus);
      
      mask = (modulus - coeff[i]) >> 15;
      coeff[i] = coeff[i] - (mask & modulus);
    }
  }

    
  public boolean equals (RingElt b) {
    int i;

    for (i = 0; i < ringEltLen; i++) 
      if (coeff[i] != b.getCoeff (i))
	return false;
    return true;
  }

    
  public String toString () {
    int degree = getDegree();
    
    String s = "[" + coeff[0];

    for (int i = 1; i < ringEltLen; i++) {
      s += ", ";
      s += coeff[i];
    }
    
    return s + "]";
  }


  private int getDegree () {
    int degree = ringEltLen - 1;

    while (coeff[degree] == 0)
      degree--;

    return degree;
  }


  public byte[] toByteArray () {
    ByteBuffer bb = ByteBuffer.allocate (ringEltLen * Integer.SIZE);
    for (int i = 0; i < ringEltLen; i++) 
      bb.putInt (i, (int) coeff[i]);
    return bb.array();
  }

}
