
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
  private byte domain;

  public RlwePublicKey (RlwePrivateKey k, RingElt a) {
    RingElt e = Sample.getSample ();
    e.multBy3 ();                               // Mult by 3 because of mod reduction optimizations
    e.ntt ();
    key = a.pointwiseMultAdd (k.getS (), e);
    key.correction ();
    domain = Constants.FOURIER;
  }


  public RlwePublicKey (RlwePrivateKey k, RingElt e, RingElt a) {
    e.multBy3 ();
    e.ntt();
    key = a.pointwiseMultAdd (k.getS (), e);
    key.correction ();
    domain = Constants.FOURIER;
  }


  public RlwePublicKey (RingElt b, byte dom) {
    key = new RingElt (b);
    domain = dom;
  }

  
  public RlwePublicKey (RlwePublicKey k) {
    key = new RingElt (k.key);
    domain = k.domain;
  }


  public RlwePublicKey (byte[] inBytes) {
    domain = inBytes[0];
    key = new RingElt (Arrays.copyOfRange (inBytes, 1, inBytes.length));
  }


  public RingElt getKey () {
    return key;
  }


  public byte getDomain () {
    return domain;
  }


  public void toFourierDomain () {
    if (domain == Constants.ORDINARY) {
      key.ntt ();
      key.multByConst (27);                     // Account for modular reduction optimizations
      domain = Constants.FOURIER;
    }
  }


  public void fromFourierDomain () {
    if (domain == Constants.FOURIER) {
      key.nttInv();
      key.multByConst (27);                     // Account for modular reduction optimizations
      domain = Constants.ORDINARY;
    }
  }
    

  public byte[] serialize () {
    byte[] kba = key.toByteArray();
    byte[] ba = new byte[kba.length + 1];
    
    ba[0] = domain;
    System.arraycopy (kba, 0, ba, 1, kba.length);
    
    return ba;
  }


  public int hashcode () {
    return Arrays.hashCode (serialize());
  }
}


class RlwePrivateKey {
  private RingElt s;
  private byte domain;

  
  public RlwePrivateKey (RingElt sIn, byte dom) {
    s = new RingElt (sIn);
    if (dom == Constants.ORDINARY)
      s.ntt();
    domain = Constants.FOURIER;
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


  public RlweKeyPair (RlwePrivateKey prKey, RingElt a, byte transmitDomain) {
    privKey = prKey;
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (prKey, a);

    if (transmitDomain == Constants.ORDINARY)
      pubKey.fromFourierDomain();
  }


  public RlweKeyPair (RlwePrivateKey prKey, RingElt e, RingElt a, byte transmitDomain) {
    privKey = prKey;
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (prKey, e, a);

    if (transmitDomain == Constants.ORDINARY) 
      pubKey.fromFourierDomain();
  }

  
  public RlweKeyPair (byte[] inKey, RingElt a, byte transmitDomain) {
    privKey = new RlwePrivateKey (inKey);
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (privKey, a);

    if (transmitDomain == Constants.ORDINARY) 
      pubKey.fromFourierDomain();
  }

  
  public RlweKeyPair (byte[] inKey, RingElt e, RingElt a, byte transmitDomain) {
    privKey = new RlwePrivateKey (inKey);
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (privKey, e, a);

    if (transmitDomain == Constants.ORDINARY) 
      pubKey.fromFourierDomain();
  }
  

  public RlweKeyPair (RingElt a, byte transmitDomain) {
    privKey = new RlwePrivateKey ();
    privKey.toFourierDomain();
    pubKey = new RlwePublicKey (privKey, a);

    if (transmitDomain == Constants.ORDINARY) 
      pubKey.fromFourierDomain();
  }


  public RlwePrivateKey getPrivateKey () {
    return privKey;
  }


  public RlwePublicKey getPublicKey () {
    return pubKey;
  }


  // Generate a new public key with the same private key but new error term
  public void genNewPubKey (RingElt a) {
    byte domain = pubKey.getDomain ();
    pubKey = new RlwePublicKey (privKey, a);
    if (domain == Constants.ORDINARY)
      pubKey.fromFourierDomain ();
  }
}
