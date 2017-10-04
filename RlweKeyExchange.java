package rlwe;

/**************************************************************************************************
 *
 * Implements RLWE key exchange algorithm. 
 *
 * Efforts to prevent timing attacks often result in increased code complexity, but the importance 
 * is sufficient enough to warrant those efforts even if it makes parts of the implementation more 
 * difficult to read or comprehend.
 *
 **************************************************************************************************/

import java.util.Arrays;
import java.math.BigInteger;
import java.util.Random;

class RlweKeyExchange {
  RingElt a;                 

  
  public RlweKeyExchange () {
    Felm.setModulus (Constants.Q);
    RingElt.initialize ();
    a = new RingElt (Constants.A);
  }
  
  
  public RingElt getA () {
    return new RingElt (a);
  }


  public RlweKeyPair generateKeyPair () {
    return new RlweKeyPair (a);
  }


  public RlweKeyPair generateKeyPair (byte[] inKey) {
    return new RlweKeyPair (inKey, a);  
  }


  public byte[][] respAgreement (RlwePrivateKey kR, RlwePublicKey kI) {
    // Compute and return: [shared secret, reconciliation data]
    byte[][] result = new byte[2][];
    
    RingElt eprime = Sample.getSample ();
    
    RingElt v = kI.getKey().pointwiseMult (kR.getS());
    v.nttInv();
    v = v.ringAdd (eprime);
    
    result[1] = helpRec (v);    
    result[0] = rec (v, result[1]);
    
    return result;
  }


  public byte[] initAgreement (RlwePrivateKey kI, RlwePublicKey kR, byte[] rdata) {
    RingElt v = kR.getKey().pointwiseMult (kI.getS());
    v.nttInv();

    return rec (v, rdata);
  }
 
 
  /* 
   * At a high level, 4 coefficients are used per bit of shared key produced. Computing 
   * reconciliation data involves finding the closest lattice vector to those 4 coefficients (as a
   * vector) and computing the discretized difference between those coefficients and the closest 
   * lattice vector. This discretized difference is the reconciliation data vector, r. It is assumed 
   * that translating a lattice point by r will move it closer to the correct lattice point. The
   * function helpRec uses an algorithm for the closest vector problem to find r, and the function 
   * rec computes reconciliation using r. The reconciliation data is 2 bits per coefficient so this
   * is compressed before being sent to reduce bandwidth.
   */

  private byte[] helpRec (RingElt v) {
    int i, j, k, x, rbit, norm;
    int[] v0 = new int[4];
    int[] v1 = new int[4];
    int[] rdata = new int[Constants.N];
    int[] xvec = v.asIntArray ();
    
    Random rnd = new Random ();
    BigInteger randbits = new BigInteger (256, rnd);
    
    for (i = 0; i < 256; i++) {
      rbit = randbits.testBit (i) ? 1 : 0;

      k = 0;
      for (j = 0; j < 4; j++) {
	x = 8 * xvec[i + 256*j] + 4 * rbit;
	v0[j] = (x + Constants.Q) / Constants.Q_TIMES_2;   // v0 = round (x/2q)
	v1[j] = x / Constants.Q_TIMES_2;                   // v1 = floor (x/2q)
	k += abs (x - v0[j] * Constants.Q_TIMES_2);        // k += amount x/2q was rounded
      }

      k = (Constants.Q_TIMES_2 - 1 - k) >> (Integer.SIZE - 1);  

      for (j = 0; j < 4; j++)
	v0[j] = ((~k) & v0[j]) ^ (k & v1[j]);              // Set v0 to the closer of v0 and v1

      rdata[i] = (v0[0] - v0[3]) & 3;
      rdata[i + 256] = (v0[1] - v0[3]) & 3;
      rdata[i + 512] = (v0[2] - v0[3]) & 3;
      rdata[i + 768] = (-k + 2 * v0[3]) & 3;
    }

    return compressRecData (rdata);
  }
  

  private int abs (int x) {
    int mask = x >> (Integer.SIZE - 1);
    return ((mask ^ x) - mask);
  }


  private byte[] compressRecData (int[] rvec) {
    byte[] cvec = new byte[Constants.numRecDataBytes];
    int i;
    
    for (i = 0; i < Constants.numRecDataBytes; i++) {
      cvec[i] = (byte) rvec[4*i];
      cvec[i] |= (byte) (rvec[4*i + 1] << 2);
      cvec[i] |= (byte) (rvec[4*i + 2] << 4);
      cvec[i] |= (byte) (rvec[4*i + 3] << 6);
    }
    
    return cvec;
  }


  private int[] decompressRecData (byte[] cvec) {
    int[] rvec = new int[Constants.N];
    int i;
    
    for (i = 0; i < Constants.numRecDataBytes; i++) {
      rvec[4*i] = cvec[i] & 3;
      rvec[4*i + 1] = (cvec[i] >> 2) & 3;
      rvec[4*i + 2] = (cvec[i] >> 4) & 3;
      rvec[4*i + 3] = (cvec[i] >> 6) & 3;
    }
    
    return rvec;
  }


  private byte[] rec (RingElt v, byte[] compressedData) {
    int i;
    int[] t = new int[4];
    int[] x = v.asIntArray ();
    int[] rdata = decompressRecData (compressedData);
    byte[] key = new byte[32];
    
    for (i = 0; i < 256; i++) {
      t[0] = Constants.Q_TIMES_16 + 8 * x[i]     - Constants.Q * (2 * rdata[i]     + rdata[i+768]);
      t[1] = Constants.Q_TIMES_16 + 8 * x[i+256] - Constants.Q * (2 * rdata[i+256] + rdata[i+768]);
      t[2] = Constants.Q_TIMES_16 + 8 * x[i+512] - Constants.Q * (2 * rdata[i+512] + rdata[i+768]);
      t[3] = Constants.Q_TIMES_16 + 8 * x[i+768] - Constants.Q * rdata[i+768];

      key[i >> 3] |= ldDecode (t) << (i & 7);
    }

    return key;
  }


  private int ldDecode (int[] t) {
    int i, norm = 0;

    for (i = 0; i < 4; i++) 
      norm += dist (t[i]);

    norm -= Constants.Q_TIMES_8;
    norm >>= (Integer.SIZE - 1);
    
    return norm & 1;
  }
  

  private int dist (int x) {
    int t;

    t = (x + Constants.Q_TIMES_4) / Constants.Q_TIMES_8;
    t *= Constants.Q_TIMES_8;
    
    return abs (t - x);
  }  
}
