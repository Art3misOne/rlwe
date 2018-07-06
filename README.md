This software is an implementation of the Ring Learning With Errors (RLWE) key exchange using the style
guide from Open Whisper Systems. This implementation largely follows the one published by Singh and
Chopra:

  - "A Practical Key Exchange for the Internet using Lattice Cryptography" by Vikram Singh.
    http://eprint.iacr.org/2015/138
  - "Even More Practical Key Exchanges for the Internet using Lattice Cryptography" by Vikram Singh and
    Arun Chopra. http://eprint.iacr.org/2015/1120.
  - www.github.com/vscrypto/ringlwe

More recent work was published by Microsoft introducing additional optimizations for Number Theoretic
Transform computations. These have now been incorporated making the average runtime per exchange
about 2.75 times faster.

  - "Speeding up the Number Theoretic Transform for Faster Ideal Lattice-Based Cryptography" by Patrick
  Longa and Michael Naehrig. https://eprint.iacr.org/2016/504.pdf.

With these optimizations, a new parameter has been introduced to facilitate compatibility between
different Fourier optimizations. Keys can either be transmitted in the Fourier domain (for greater
efficiency) or the Ordinary domain (for interoperability). Preliminary tests indicate that it takes
about 1.17 times as long to complete an exchange transmitting in the ordinary domain than in the
Fourier domain.

Note of caution: This implementation (and the RLWE key exchange in general) is not a drop-in
replacement for ECDH. In ECDH, both parties generate a key pair, transmit their public keys,
and compute the shared agreement from their own private key and the other party's public key.

       Generate key pair                               Generate key pair
       Transmit public key                             Transmit public key
       Wait (receive public key)                       Wait (receive public key)
       Agreement (their public, my private)            Agreement (their public, my private)

The only required synchronicity is that one must receive the other party's public key before computing
the shared agreement. In RLWE, one party must compute the reconciliation data which both parties
use for computing the shared key.

       Generate key pair                               Generate key pair
       Transmit public key
	                                               Wait (receive public key)
	                                               Compute rec data
						       Transmit public key and rec data
       Wait (receive pub key, rec data)                Agreement (their public, my private, rec data)
       Agreement (their public, my private, rec data)

Greater synchronicity is required and care must be taken when replacing an existing key exchange with
RLWE.
