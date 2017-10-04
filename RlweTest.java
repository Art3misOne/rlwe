package rlwe;

/**************************************************************************************************
 *
 * Basic tests for the RLWE key exchange.
 *
 **************************************************************************************************/

import java.math.BigInteger;
import java.util.Arrays;

class RlweTest {

  public static void main (String[] args) {
    int m = 1024;
    int q = 12289;
    
    RlweKeyExchange kex = new RlweKeyExchange ();
    byte[] recData, secretI, secretR;
    byte[][] response;
    RlweKeyPair keysI, keysR;

    long startTime, endTime, totalTime = 0;
    int i, iterations = 100;
    
    for (i = 0; i < iterations; i++) {
      startTime = System.nanoTime();
      keysI = kex.generateKeyPair ();
      keysR = kex.generateKeyPair ();
      
      System.out.print ("Testing key exchange with randomly generated keys... ");

      /*
      System.out.println ("Initiator private key: ");
      System.out.println ("\t s = " + keysI.getPrivateKey().getS());
      System.out.println ("\t e = " + keysI.getPrivateKey().getE() + "\n");
      
      System.out.println ("Initiator public key: ");
      System.out.println ("\t k = " + keysI.getPublicKey().getKey() + "\n");
      
      System.out.println ("Responder private key: ");
      System.out.println ("\t s = " + keysR.getPrivateKey().getS());
      System.out.println ("\t e = " + keysR.getPrivateKey().getE() + "\n");
      
      System.out.println ("Responder public key: ");
      System.out.println ("\t k = " + keysR.getPublicKey().getKey() + "\n");
      */
	
      response = kex.respAgreement (keysR.getPrivateKey(), keysI.getPublicKey());
      secretR = response[0];
      recData = response[1];
      
      secretI = kex.initAgreement (keysI.getPrivateKey(), keysR.getPublicKey(), recData);
    
      if (Arrays.equals (secretI, secretR)) {
	System.out.print ("Shared secrets match :)\nShared secret = ");
	printByteArray (secretI);
	System.out.println ("\n");
      }

      else {
	System.out.print ("Shared secrets do not match :(\n secretI = ");
	printByteArray (secretI);
	System.out.print ("\n secretR = ");
	printByteArray (secretR);
	System.out.println ("\n");
      }
      
      endTime = System.nanoTime();
      totalTime += (endTime - startTime) / 1000;  // convert nanoseconds to microseconds
    }

    System.out.println ("Time for " + iterations + " iterations: " + totalTime + " microseconds\n");
  }


  public static void printByteArray (byte[] in) {
    System.out.print ("0x");
    for (int i = 0; i < in.length; i++)
      System.out.printf ("%02x ", in[i]);
  }
}
