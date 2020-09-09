package com.android.javacard.keymaster;

public interface KMAttestationCert {
  KMAttestationCert verifiedBootHash(short obj);

  KMAttestationCert authKey(short obj);

  KMAttestationCert verifiedBootKey(short obj);

  KMAttestationCert verifiedState(byte val);

  KMAttestationCert uniqueId(short obj);
  KMAttestationCert notBefore(short obj);
  KMAttestationCert notAfter(short obj);

  KMAttestationCert deviceLocked(boolean val);

  KMAttestationCert publicKey(short obj);
  KMAttestationCert attestationChallenge(short obj);
  KMAttestationCert extensionTag(short tag, boolean hwEnforced);
  KMAttestationCert issuer(short obj);
  short getCertLength();

  KMAttestationCert buffer(byte[] buf, short bufStart, short maxLen);

  KMAttestationCert signingKey(short privKey, short modulus);

  short getCertStart();

  short getCertEnd();

  void build();
}
