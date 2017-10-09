
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
    RingElt e = Sample.getSample ();
    e.ntt ();
    key = a.pointwiseMultAdd (k.getS (), e);
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
  private byte domain;

  public RlwePrivateKey (RingElt sIn) {
    s = new RingElt (sIn);
  }


  public RlwePrivateKey () {
    s = Sample.getSample ();
    domain = Constants.ORDINARY;
  }


  public RlwePrivateKey (byte[] inBytes) {
    domain = inBytes[0];
    s = new RingElt (Arrays.copyOfRange (inBytes, 1, inBytes.length));
  }


  public RingElt getS () {
    return s;
  }
  

  public void toFourierDomain () {
    if (domain == Constants.ORDINARY) {
      s.ntt();
      domain = Constants.FOURIER;
    }
  }


  public void fromFourierDomain () {
    if (domain == Constants.FOURIER) {
      s.nttInv();
      domain = Constants.ORDINARY;
    }
  }

  
  public byte[] serialize () {
    byte[] sba = s.toByteArray();
    byte[] ba = new byte[sba.length + 1];
    
    ba[0] = domain;
    System.arraycopy (sba, 0, ba, 1, sba.length);
    
    return ba;
  }
}


class RlweKeyPair {
  private RlwePublicKey pubKey; 
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


  // Generate a new public key with the same private key but new error term
  public void genNewPubKey (RingElt a) {
    pubKey = new RlwePublicKey (privKey, a);
  }
}
