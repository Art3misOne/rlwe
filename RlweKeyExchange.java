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
  byte aDomain;
  byte transmitDomain;
  
  public RlweKeyExchange () {
    RingElt.initialize ();
    transmitDomain = Constants.ORDINARY;
    a = new RingElt (Constants.A);
    a.ntt ();
    aDomain = Constants.FOURIER;
  }


  public RlweKeyExchange (RingElt aIn, byte aDom, byte tDom) {
    RingElt.initialize ();
    transmitDomain = tDom;
    a = new RingElt (aIn);
    if (aDom == Constants.ORDINARY)
      a.ntt ();
    aDomain = Constants.FOURIER;
  }
    
  
  public RingElt getA () {
    return new RingElt (a);
  }


  public RlweKeyPair generateKeyPair () {
    return new RlweKeyPair (a, transmitDomain);
  }


  public RlweKeyPair generateKeyPair (byte[] inKey) {
    return new RlweKeyPair (inKey, a, transmitDomain);  
  }


  public byte[][] respAgreement (RlwePrivateKey kR, RlwePublicKey kI) {
    // Compute and return: [shared secret, reconciliation data]
    byte[][] result = new byte[2][];
    
    RingElt eprime = Sample.getSample ();

    if (transmitDomain == Constants.ORDINARY) 
      kI.toFourierDomain ();
    
    RingElt v = kI.getKey().pointwiseMult (kR.getS ());
    v.nttInv();
    v.ringAdd (eprime);

    result[1] = helpRec (v);    
    result[0] = rec (v, result[1]);
    
    return result;
  }


  // For testing purposes
  public byte[][] respAgreement (RlwePrivateKey kR, RlwePublicKey kI, RingElt eprime) {
    // Compute and return: [shared secret, reconciliation data]
    byte[][] result = new byte[2][];

    if (transmitDomain == Constants.ORDINARY) 
      kI.toFourierDomain ();
      
    RingElt v = kI.getKey().pointwiseMult (kR.getS ());
    v.nttInv();
    v = v.ringAdd (eprime);

    result[1] = helpRec (v);    
    result[0] = rec (v, result[1]);
    
    return result;
  }  

  
  public byte[] initAgreement (RlwePrivateKey kI, RlwePublicKey kR, byte[] rdata) {
    if (transmitDomain == Constants.ORDINARY) 
      kR.toFourierDomain ();
    
    RingElt v = kR.getKey().pointwiseMult (kI.getS ());
    v.nttInv();

    return rec (v, rdata);
  }
 
 
  private byte[] helpRec (RingElt v) {
    int i, j, k, x, rbit, norm;
    int[] v0 = new int[4];
    int[] v1 = new int[4];
    int[] rdata = new int[Constants.N];
    long[] xvec = v.getCoeffs ();
    
    Random rnd = new Random ();
    BigInteger randbits = new BigInteger (256, rnd);
    
    for (i = 0; i < 256; i++) {
      rbit = randbits.testBit (i) ? 1 : 0;

      k = 0;
      for (j = 0; j < 4; j++) {
	x = 8 * (int) xvec[i + 256*j] + 4 * rbit;
	v0[j] = (x + Constants.Q) / Constants.Q2;   // v0 = round (x/2q)
	v1[j] = x / Constants.Q2;                   // v1 = floor (x/2q)
	k += abs (x - v0[j] * Constants.Q2);        // k += amount x/2q was rounded
      }

      k = (Constants.Q2 - 1 - k) >> (Integer.SIZE - 1);  

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
    long[] x = v.getCoeffs ();
    int[] rdata = decompressRecData (compressedData);
    byte[] key = new byte[32];
    
    for (i = 0; i < 256; i++) {
      t[0] = Constants.Q16 + 8 * (int) x[i]     - Constants.Q * (2 * rdata[i]     + rdata[i+768]);
      t[1] = Constants.Q16 + 8 * (int) x[i+256] - Constants.Q * (2 * rdata[i+256] + rdata[i+768]);
      t[2] = Constants.Q16 + 8 * (int) x[i+512] - Constants.Q * (2 * rdata[i+512] + rdata[i+768]);
      t[3] = Constants.Q16 + 8 * (int) x[i+768] - Constants.Q * rdata[i+768];

      key[i >> 3] |= ldDecode (t) << (i & 7);
    }

    return key;
  }


  private int ldDecode (int[] t) {
    int i, norm = 0;

    for (i = 0; i < 4; i++) 
      norm += dist (t[i]);

    norm -= Constants.Q8;
    norm >>= (Integer.SIZE - 1);
    
    return norm & 1;
  }
  

  private int dist (int x) {
    int t;

    t = (x + Constants.Q4) / Constants.Q8;
    t *= Constants.Q8;
    
    return abs (t - x);
  }  
}
