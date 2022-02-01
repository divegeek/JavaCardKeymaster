/*
 * Copyright(C) 2022 The Android Open Source Project
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

package com.android.javacard.kmdevice;

public interface KMDataStore extends KMUpgradable {

  /**
   * This function stores the data of the corresponding id into the persistent memory.
   *
   * @param id of the buffer to be stored. @see {@link KMDataStoreConstants}
   * @param data is the buffer that contains the data to be stored.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   */
  void storeData(byte id, byte[] data, short offset, short length);

  /**
   * This function returns the stored data of the corresponding id.
   *
   * @param id of the buffer to be stored.@see {@link KMDataStoreConstants}
   * @param data is the buffer in which the data of the corresponding id is returned.
   * @param offset is the start offset of the buffer.
   * @return length of the data copied to the buffer.
   */
  short getData(byte id, byte[] data, short offset);

  /**
   * This function clears the data of the corresponding id in persistent memory.
   *
   * @param id of the buffer to be stored. @see {@link KMDataStoreConstants}
   */
  void clearData(byte id);

  // Below functions are used to store and retrieve the auth tags for
  // MAX_USES_PER_BOOT use case.

  /**
   * This function stores the Auth tag associated with keyblob.
   *
   * @param data is the buffer containing the auth tag.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   * @param scracthPad is the buffer used to copy intermediate results.
   * @param scratchPadOff is the start offset of the scratchPad.
   * @return true if successfully copied otherwise false.
   */
  boolean storeAuthTag(byte[] data, short offset, short length, byte[] scracthPad,
      short scratchPadOff);

  /**
   * This function checks if the auth tag is presisted in the database.
   *
   * @param data is the buffer containing the auth tag.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   * @param scratchPad is the buffer used to copy intermediate results.
   * @param scratchPadOff is the start offset of the scratchPad.
   * @return true if successfully copied otherwise false.
   */
  boolean isAuthTagPersisted(byte[] data, short offset, short length, byte[] scratchPad,
      short scratchPadOff);

  /**
   * Clears all the persisted auth tags.
   */
  void clearAllAuthTags();

  /**
   * This functions returns count, the number of times keyblob is used.
   *
   * @param data is the buffer containing the auth tag.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   * @param scratchPad is out buffer where the count is copied.
   * @param scratchPadOff is the start offset of the scratchPad.
   * @return length of the counter buffer.
   */
  short getRateLimitedKeyCount(byte[] data, short offset, short length, byte[] scratchPad,
      short scratchPadOff);

  /**
   * This functions copied the count into the persistent memory.
   *
   * @param data is the buffer containing the auth tag.
   * @param offset is the start offset of the buffer.
   * @param length is the length of the buffer.
   * @param counter is the buffer containing the counter values.
   * @param counterOff is the start offset of the counter buffer.
   * @param counterLen is the length of the counter buffer.
   * @param scratchPad is the buffer used to copy intermediate results.
   * @param scratchPadOff is the start offset of the scratchPad.
   */
  void setRateLimitedKeyCount(byte[] data, short offset, short length, byte[] counter,
      short counterOff,
      short counterLen, byte[] scratchPad, short scratchPadOff);

  /**
   * Stores the certificate chain, certificate issuer and certificate expire date in persistent
   * memory.
   *
   * @param buffer is the buffer containing certificate chain, issuer and expire at different
   * offets.
   * @param certChainOff is the start offset of the certificate chain.
   * @param certChainLen is the length of the certificate chain.
   * @param certIssuerOff is the start offset of the certificate issuer.
   * @param certIssuerLen is the length of the certificate issuer.
   * @param certExpiryOff is the start offset of the certificate expire date.
   * @param certExpiryLen is the length of the certificate expire date.
   */
  void persistCertificateData(byte[] buffer, short certChainOff, short certChainLen,
      short certIssuerOff,
      short certIssuerLen, short certExpiryOff, short certExpiryLen);

  /**
   * This function copies the requested certificate data into the provided out buffer.
   *
   * @param reqCertParam is the requested certificate parameter. @see {@link
   * KMDataStoreConstants#CERTIFICATE_CHAIN} {@link KMDataStoreConstants#CERTIFICATE_ISSUER} {@link
   * KMDataStoreConstants#CERTIFICATE_EXPIRY}
   * @param buf is the out buffer where the requested data is copied.
   * @param offset is the start offset of the out buffer.
   * @return length of the returned data.
   */
  short readCertificateData(byte reqCertParam, byte[] buf, short offset);

  /**
   * This function returns the length of the requested certificate data requested.
   *
   * @param reqCertParam is the requested certificate parameter. @see {@link
   * KMDataStoreConstants#CERTIFICATE_CHAIN} {@link KMDataStoreConstants#CERTIFICATE_ISSUER} {@link
   * KMDataStoreConstants#CERTIFICATE_EXPIRY}
   * @return length of the requested certificate data.
   */
  short getCertificateDataLength(byte reqCertParam);

  // keys

  /**
   * Returns the persisted computed hmac key.
   *
   * @return KMComputedHmacKey instance.
   */
  KMComputedHmacKey getComputedHmacKey();

  /**
   * Returns the pre-shared key.
   *
   * @return KMPreSharedKey instance.
   */
  KMPreSharedKey getPresharedKey();

  /**
   * Returns the master key.
   *
   * @return KMMasterKey instance.
   */
  KMMasterKey getMasterKey();

  /**
   * Returns the attestation key.
   *
   * @return KMAttestationKey instance.
   */
  KMAttestationKey getAttestationKey();

}
