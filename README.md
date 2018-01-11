This software is an implementation of the Ring Learning With Errors (RLWE) key exchange compatible with
the Signal framework and style guide. This implementation largely follows the one published by Singh
and Chopra:

  - "A Practical Key Exchange for the Internet using Lattice Cryptography" by Vikram Singh.
    http://eprint.iacr.org/2015/138
  - "Even More Practical Key Exchanges for the Internet using Lattice Cryptography" by Vikram Singh and
    Arun Chopra. http://eprint.iacr.org/2015/1120.
  - www.github.com/vscrypto/ringlwe

More recent work was published by Microsoft introducing additional optimizations. These optimizations
are in progress and will be included in a future version of this implementation.

Their implementation includes a wide range of options including 4 variations of sampling, 11 parameter
sets (providing various levels of security), and 2 reconciliation mechanisms. Including a wide variety
of options is suitable for general purpose code, but the Signal ideology strongly advocates for simple,
easy to read code and discourages inclusion of too many options. Thus, for this implementation it was
preferable to make defensible design decisions rather than including the various options. These
decisions were:

  - Binomial sampling
    - Justification: See "Post Quantum Key Exchange - a New Hope" by Erdem Alkim, Leo Ducas,
      Thomas Poppelmann, and Peter Schwabe. http://eprint.iacr.org/2015/1092. They argue that
      binomial sampling is much faster and does not decrease the security in any significant way.
  - New Hope reconciliation
    - Justification: The above paper also presents the New Hope reconciliation mechanism and explain
      how it improves the security.
  - N = 1024, q = 12289
    - Justification: These are the most common parameters and provide approximately 256 bits of
      security.
  - All ring elements are kept in the Fourier domain until it is necessary to invert the transform.
    - Justification: This improves efficiency by reducing the number of transforms.

This implementation is not a straight-forward translation from an existing C implementation into Java
as more adaptation was require to match the Signal framework.

Note of caution: This implementation (and the RLWE key exchange in general) is not a drop-in
replacement for ECDH. In ECDH and SIDH, both parties generate a key pair, transmit their public keys,
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
