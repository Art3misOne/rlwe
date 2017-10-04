package rlwe;

/**************************************************************************************************
 *
 * Implements a class for elements of a polynomial ring with Felm coefficients for the RLWE Key 
 * Exchange. 
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
  private Felm[] coeff;

  // Precomputed values to improve efficiency of number theoretic transforms
  private static Felm[] omega;               // roots of unity
  private static Felm[] omegaInv;            // inverses of roots of unity
  private static Felm[] omegaSqrt;           // square roots of roots of unity
  private static Felm[] omegaSqrtInv;        // square roots of inverse roots of unity
  private static Felm nInv;                  // n^-1 mod q

  
  public RingElt () {
    coeff = new Felm[ringEltLen];

    for (int i = 0; i < ringEltLen; i++)
      coeff[i] = new Felm();
  }


  // Change the following two functions to throw exceptions when the array length is incorrect
  public RingElt (int[] coefficient) {
    int i, diff = ringEltLen - coefficient.length;
    
    if (diff < 0) {
      ringEltLen = coefficient.length;
      diff = 0;
    }
    
    coeff = new Felm[ringEltLen];
    for (i = 0; i < coefficient.length; i++)
      coeff[i] = new Felm (coefficient[i]);
    for (i = coefficient.length; i < ringEltLen; i++)
      coeff[i] = new Felm ();
  } 


  public RingElt (Felm[] coefficient) {
    int i, diff = ringEltLen - coefficient.length;

    if (diff < 0) {
      ringEltLen = coefficient.length;
      diff = 0;
    }
    
    coeff = new Felm[ringEltLen];
    for (i = 0; i < diff; i++)
      coeff[i] = new Felm();
    for (i = diff; i < ringEltLen; i++)
      coeff[i] = new Felm (coefficient[i-diff]);
  }


  public RingElt (RingElt b) {
    coeff = new Felm[ringEltLen];

    for (int i = 0; i < ringEltLen; i++)
      coeff[i] = new Felm (b.getCoeff(i));    
  }


  public RingElt (byte[] inBytes) {
    int bytesPerCoeff = inBytes.length / ringEltLen;
    int x;

    coeff = new Felm[ringEltLen];

    for (int i = 0; i < ringEltLen; i++) {
      x = 0;
    
      for (int j = 0; j < bytesPerCoeff; j++)
	x += (int) inBytes[i*bytesPerCoeff + j] << (8 * (bytesPerCoeff - j));
      
      coeff[i] = new Felm (x);
    }
  }


  public static void initialize () {
    omega = Constants.OMEGA;
    omegaInv = Constants.OMEGA_INV;
    omegaSqrt = Constants.OMEGA_SQRT;
    omegaSqrtInv = Constants.OMEGA_SQRT_INV;
    nInv = new Felm (Constants.N_INV);
  }
  
  
  static int getLength () {
    return ringEltLen;
  }

  
  Felm getCoeff (int index) {
    if (index >= ringEltLen || index < 0)
      return Felm.ZERO;
    return coeff[index];
  }


  void setCoeff (int index, Felm value) {
    if (ringEltLen > index && index >= 0)
      coeff[index] = value;
  }


  void setCoeff (int index, int value) {
    setCoeff (index, new Felm(value));
  }


  int[] asIntArray () {
    int[] r = new int[ringEltLen];

    for (int i = 0; i < ringEltLen; i++)
      r[i] = coeff[i].fqGetValue();

    return r;
  }
  

  RingElt ringAdd (RingElt a) {
    RingElt c = new RingElt ();

    for (int i = 0; i < ringEltLen; i++) {
      Felm ci = coeff[i].fqAdd (a.getCoeff(i));
      c.setCoeff (i, ci);
    }

    return c;
  }


  RingElt pointwiseMult (RingElt a) {
    RingElt c = new RingElt ();
    for (int i = 0; i < ringEltLen; i++)
      c.setCoeff (i, coeff[i].fqMult (a.getCoeff(i)));
    return c;
  }


  RingElt pointwiseMultAdd (RingElt a, RingElt b) {
    RingElt c = new RingElt ();
    Felm t;

    for (int i = 0; i < ringEltLen; i++) {
      t = coeff[i].fqMult (a.getCoeff(i));
      t = t.fqAdd (b.getCoeff(i));
      c.setCoeff (i, t);
    }

    return c;
  }

  // The next two functions below compute forward and inverse number theoretic transforms.
  //
  // Decimation-in-frequency: expects input in natural order, produces output in bit-reversed order
  // Decimation-in-time: expects input in bit-reversed order, produces output in natural order
  //
  // As noted by Singh and Chopra, a bit reversal on the indices is ordinarily required to account
  // for the scrambled order, but it can be avoided by using decimation-in-frequency for the 
  // forward transform and decimation-in-time for the inverse transform .

  // Uses Gentleman-Sande decimation-in-frequency. 
  void ntt () {
    int m, j, i, index, step;
    Felm t0, t1;
    
    for (i = 0; i < (ringEltLen >> 1); ++i) {
      coeff[2*i] = coeff[2*i].fqMult (omega[i]);
      coeff[2*i+1] = coeff[2*i+1].fqMult (omegaSqrt[i]);
    }
    
    step = 1;
    for (m = ringEltLen >> 1; m >= 1; m = m >> 1) {
      index = 0;
      for (j = 0; j < m; ++j) {
        for (i = j; i < ringEltLen; i += m << 1) {
	  t0 = coeff[i].fqAdd (coeff[i+m]);
	  t1 = coeff[i].fqSub (coeff[i+m]);
	  coeff[i+m] = t1.fqMult (omega[index]);
	  coeff[i] = new Felm (t0);
	}

	index = (index - step + ringEltLen) % ringEltLen;
      }

      step = step << 1;
    }
  }


  // Uses Cooley-Tukey decimation-in-time.
  void nttInv () {
    int m, j, i, index, step;
    Felm t0, t1;

    step = ringEltLen >> 1;
    for (m = 1; m < ringEltLen; m = m << 1) {
      index = 0;
      for (j = 0; j < m; ++j) {
        for (i = j; i < ringEltLen; i += m << 1) {
	  t0 = new Felm (coeff[i]);
	  t1 = coeff[i+m].fqMult (omegaInv[index]);
	  coeff[i] = t0.fqAdd (t1);
	  coeff[i+m] = t0.fqSub(t1);
	}

	index = (index - step + ringEltLen) % ringEltLen;
      }

      step = step >> 1;
    }

    for (i = 0; i < (ringEltLen >> 1); ++i) {
      coeff[2*i] = coeff[2*i].fqMult (omegaInv[i]);
      coeff[2*i+1] = coeff[2*i+1].fqMult (omegaSqrtInv[i]);
    }

    for (i = 0; i < ringEltLen; i++)
      coeff[i] = coeff[i].fqMult(nInv);
  }


  public String toString () {
    int degree = getDegree();
    
    String s = "(" + getCoeff(0);

    for (int i = 1; i <= degree; i++) {
      s += ", ";
      if ((i%12) == 11)
	s += "\n";
       s += getCoeff(i);
    }
    
    return s + ")";
  }


  private int getDegree () {
    int degree = ringEltLen - 1;

    while (coeff[degree].fqIsZero())
      degree--;

    return degree;
  }


  public byte[] toByteArray () {
    ByteBuffer bb = ByteBuffer.allocate (ringEltLen * Integer.SIZE);
    for (int i = 0; i < ringEltLen; i++) 
      bb.putInt (i, coeff[i].fqGetValue());
    return bb.array();
  }

}
