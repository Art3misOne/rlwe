
package rlwe;

/**************************************************************************************************
 *
 * Implements objects for public and private keys including key generation functions.
 *
 * To improve efficiency, all elements are kept in the Fourier domain and only translated back to
 * compute the shared key at the end. This avoids converting back and forth each time a ring elt
 * multiplication is performed.
 *  
 **************************************************************************************************/

import java.math.BigInteger;
import java.util.Arrays;


class RlwePublicKey {
  private RingElt key;


  public RlwePublicKey (RlwePrivateKey k, RingElt a) {
    key = a.pointwiseMultAdd(k.getS (), k.getE ());
  }


  public RlwePublicKey (RingElt b) {
    key = new RingElt (b);
  }

  
  public RlwePublicKey (RlwePublicKey k) {
    key = new RingElt (k.key);
  }


  public RlwePublicKey (byte[] inBytes) {
    key = new RingElt (inBytes);
  }


  public RingElt getKey () {
    return key;
  }

  
  public byte[] serialize () {
    return key.toByteArray();
  }


  public int hashcode () {
    return Arrays.hashCode (serialize());
  }
}


class RlwePrivateKey {
  private RingElt s;
  private RingElt e;


  public RlwePrivateKey (RingElt sIn, RingElt eIn) {
    s = new RingElt (sIn);
    e = new RingElt (eIn);
  }


  public RlwePrivateKey () {
    s = Sample.getSample ();
    e = Sample.getSample ();
  }


  public RlwePrivateKey (byte[] inBytes) {
    // Reconstruct a private key from a byte array assuming s and e are the same size.
    int len = inBytes.length;
    s = new RingElt (Arrays.copyOfRange (inBytes, 0, len / 2)); 
    e = new RingElt (Arrays.copyOfRange (inBytes, len / 2, len));
  }


  public RingElt getS () {
    return s;
  }
  

  public RingElt getE () {
    return e;
  }


  public void toFourierDomain () {
    s.ntt();
    e.ntt();
  }


  public void fromFourierDomain () {
    s.nttInv();
    e.nttInv();
  }

  
  public byte[] serialize () {
    byte[] sba = s.toByteArray ();
    byte[] eba = e.toByteArray ();
    byte[] r = new byte[sba.length + eba.length];
    System.arraycopy (sba, 0, r, 0, sba.length);
    System.arraycopy (eba, 0, r, sba.length, eba.length);
    return r;
  }
}


class RlweKeyPair {
  private final RlwePublicKey pubKey; 
  private final RlwePrivateKey privKey;


  public RlweKeyPair (RlwePrivateKey prKey, RingElt a) {
    privKey = prKey;
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (prKey, a);
  }


  public RlweKeyPair (byte[] inKey, RingElt a) {
    privKey = new RlwePrivateKey (inKey);
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (privKey, a);
  }
  

  public RlweKeyPair (RingElt a) {
    privKey = new RlwePrivateKey ();
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (privKey, a);
  }


  public RlwePrivateKey getPrivateKey () {
    return privKey;
  }


  public RlwePublicKey getPublicKey () {
    return pubKey;
  }
}
