/*
 * Copyright(C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
   * @param obj This is a KMByteBlob containing hash
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootHash(short obj);

  /**
   * Set verified boot key received during booting up.
   *
   * @param obj This is a KMByteBlob containing verified boot key.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootKey(short obj);

  /**
   * Set verified boot state received during booting up.
   *
   * @param val This is a byte containing verified boot state value.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert verifiedBootState(byte val);

  /**
   * Set uniqueId received from CA certificate during provisioning.
   *
   * @param scratchpad Buffer to store intermediate results.
   * @param scratchPadOff Start offset of the scratchpad buffer.
   * @param creationTime This buffer contains the CREATION_TIME value.
   * @param creationTimeOff Start offset of creattionTime buffer.
   * @param creationTimeLen Length of the creationTime buffer.
   * @param attestAppId This buffer contains the ATTESTATION_APPLICATION_ID value.
   * @param attestAppIdOff Start offset of the attestAppId buffer.
   * @param attestAppIdLen Length of the attestAppId buffer.
   * @param resetSinceIdRotation This holds the information of RESET_SINCE_ID_ROTATION.
   * @param instance of the master key.
   * @return instance of KMAttestationCert.
   */
  KMAttestationCert makeUniqueId(byte[] scratchpad, short scratchPadOff, byte[] creationTime,
      short creationTimeOff, short creationTimeLen, byte[] attestAppId,
      short attestAppIdOff, short attestAppIdLen, byte resetSinceIdRotation,
      KMMasterKey masterKey);

  /**
   * Set start time received from creation/activation time tag. Used for certificate's valid
   * period.
   *
   * @param obj This is a KMByteBlob object containing start time.
   * @param scratchpad Buffer to store intermediate results.
   * @return instance of KMAttestationCert.
   */
  KMAttestationCert notBefore(short obj, byte[] scratchpad);


  /**
   * Set expiry time received from expiry time tag or ca certificates expiry time. Used for
   * certificate's valid period.
   *
   * @param usageExpiryTimeObj This is a KMByteBlob containing expiry time.
   * @param certExpirtyTimeObj This is a KMByteblob containing expirty time extracted from
   * certificate.
   * @param scratchpad Buffer to store intermediate results.
   * @param offset Variable used to store intermediate results.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert notAfter(short usageExpiryTimeObj,
      short certExpirtyTimeObj, byte[] scratchPad, short offset);

  /**
   * Set device lock status received during booting time or due to device lock command.
   *
   * @param val This is true if device is locked.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert deviceLocked(boolean val);

  /**
   * Set public key to be attested received from attestKey command.
   *
   * @param obj This is KMByteBlob containing the public key.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert publicKey(short obj);

  /**
   * Set attestation challenge received from attestKey command.
   *
   * @param obj This is KMByteBlob containing the attestation challenge.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert attestationChallenge(short obj);

  /**
   * Set extension tag received from key characteristics which needs to be added to android
   * extension. This method will called once for each tag.
   *
   * @param tag is the KMByteBlob containing KMTag.
   * @param hwEnforced is true if the tag has to be added to hw enforced list or else added to sw
   * enforced list.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert extensionTag(short tag, boolean hwEnforced);

  /**
   * Set ASN.1 encoded X509 issuer field received from attestation key CA cert.
   *
   * @param obj This is KMByteBlob containing the issuer.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert issuer(short obj);

  /**
   * Set byte buffer to be used to generate certificate.
   *
   * @param buf This is byte[] buffer.
   * @param bufStart This is short start offset.
   * @param maxLen This is short length of the buffer.
   * @return instance of KMAttestationCert
   */
  KMAttestationCert buffer(byte[] buf, short bufStart, short maxLen);

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
   */
  void build();
}
