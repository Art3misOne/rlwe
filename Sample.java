package rlwe;

/*************************************************************************************************
 *
 * Implements sampling for use with the RLWE Key Exchange.
 *
 *************************************************************************************************/

import java.math.BigInteger;
import java.util.Random;


class Sample {
  static final int BINOMIAL_ITERATIONS = 16;


  public static RingElt getSample () {
    int i, j, b0, b1, offset, m = RingElt.getLength();
    int[] s = new int[m];
    Random rand = new Random ();
    int numbits = m * BINOMIAL_ITERATIONS;
    BigInteger randbits0 = new BigInteger (numbits, rand);
    BigInteger randbits1 = new BigInteger (numbits, rand);

    for (i = 0; i < m; i++) {
      offset = i * BINOMIAL_ITERATIONS;
      for (j = 0; j < BINOMIAL_ITERATIONS; j++) {
        b0 = boolToInt (randbits0.testBit (offset + j));
        b1 = boolToInt (randbits1.testBit (offset + j));
	s[i] += b1 - b0;
      }
    }

    return new RingElt (s);
  }  


  private static int boolToInt (boolean b) {
    if (b) return 1;
    return 0;
  }    
}
