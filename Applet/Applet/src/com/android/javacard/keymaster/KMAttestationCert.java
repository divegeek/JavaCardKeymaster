package com.android.javacard.keymaster;

/**
 * The KMAttestationCert interface represents a X509 compliant attestation certificate required to
 * support keymaster's attestKey function. This cert will be created according to the specifications
 * given in android keymaster hal documentation. KMSeProvider has to provide the instance of this
 * certificate. This interface is designed based on builder pattern and hence each method returns
 * instance of cert.
 */
public interface KMAttestationCert {
  /**
   * Set verified boot hash.
   *
   * @param obj Ths is a KMByteBlob containing hash
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootHash(short obj);

  /**
   * Set verified boot key received during booting up.
   *
   * @param obj Ths is a KMByteBlob containing verified boot key.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootKey(short obj);

  /**
   * Set verified boot state received during booting up.
   *
   * @param val Ths is a byte containing verified boot state value.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootState(byte val);

  /**
   * Set authentication key Id from CA Certificate set during provisioning.
   *
   * @param obj Ths is a KMByteBlob containing authentication Key Id.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert authKey(short obj);

  /**
   * Set uniqueId received from CA certificate during provisioning.
   *
   * @param obj Ths is a KMByteBlob containing uniqueId.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert uniqueId(short obj);

  /**
   * Set start time received from creation/activation time tag. Used for certificate's valid period.
   *
   * @param obj Ths is a KMByteBlob containing start time.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert notBefore(short obj);

  /**
   * Set expiry time received from expiry time tag or ca certificates expiry time.
   * Used for certificate's valid period.
   *
   * @param obj Ths is a KMByteBlob containing expiry time.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert notAfter(short obj);

  /**
   * Set device lock status received during booting time or due to device lock command.
   *
   * @param val Ths is true if device is locked.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert deviceLocked(boolean val);

  /**
   * Set public key to be attested received from attestKey command.
   *
   * @param obj Ths is KMByteBlob containing the public key.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert publicKey(short obj);

  /**
   * Set attestation challenge received from attestKey command.
   *
   * @param obj Ths is KMByteBlob containing the attestation challenge.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert attestationChallenge(short obj);

  /**
   * Set extension tag received from key characteristics which needs to be added to android extension.
   * This method will called once for each tag.
   *
   * @param tag is the KMByteBlob containing KMTag.
   * @param hwEnforced is true if the tag has to be added to hw enforced list or
   *                    else added to sw enforced list.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert extensionTag(short tag, boolean hwEnforced);

  /**
   * Set ASN.1 encoded X509 issuer field received from attestation key CA cert.
   *
   * @param obj Ths is KMByteBlob containing the issuer.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert issuer(short obj);

  /**
   * Set byte buffer to be used to generate certificate.
   *
   * @param buf Ths is byte[] buffer.
   * @param bufStart Ths is short start offset.
   * @param maxLen Ths is short length of the buffer.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert buffer(byte[] buf, short bufStart, short maxLen);

  /**
   * Set signing key to be used to sign the cert.
   *
   * @param privateKey Ths is rsa 2048 bit private key.
   * @param modulus Ths is rsa 2048 bit modulus.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert signingKey(short privateKey, short modulus);

  /**
   * Get the start of the certificate
   *
   * @return start of the attestation cert.
   */
  short getCertStart();

  /**
   * Get the end of the certificate
   *
   * @return end of the attestation cert.
   */
  short getCertEnd();

  /**
   * Get the length of the certificate
   *
   * @return length of the attestation cert.
   */
  short getCertLength();

  /**
   * Build the certificate. After this method the certificate is ready.
   *
   */
  void build();
}
