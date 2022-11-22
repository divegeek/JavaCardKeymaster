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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.seprovider;

import org.globalplatform.upgrade.Element;

/**
 * KMSEProvider is facade to use SE specific methods. The main intention of this interface is to
 * abstract the cipher, signature and backup and restore related functions. The instance of this
 * interface is created by the singleton KMSEProviderImpl class for each provider. At a time there
 * can be only one provider in the applet package.
 */
public interface KMSEProvider {

  /**
   * This function tells if boot signal event is supported or not.
   *
   * @return true if supported, false otherwise.
   */
  boolean isBootSignalEventSupported();

  /**
   * This function tells if the device is booted or not.
   *
   * @return true if device booted, false otherwise.
   */
  boolean isDeviceRebooted();

  /**
   * This function is supposed to be used to reset the device booted stated after set boot param is
   * handled
   *
   * @param resetBootFlag is false if event has been handled
   */
  void clearDeviceBooted(boolean resetBootFlag);
  
  /**
   * Create a symmetric key instance. If the algorithm and/or keysize are not supported then it
   * should throw a CryptoException.
   *
   * @param alg will be KMType.AES, KMType.DES or KMType.HMAC.
   * @param keysize will be 128 or 256 for AES or DES. It can be 64 to 512 (multiple of 8) for
   * HMAC.
   * @param buf is the buffer in which key has to be returned
   * @param startOff is the start offset.
   * @return length of the data in the buf. This should match the keysize (in bytes).
   */
  short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff);

  /**
   * Create a asymmetric key pair. If the algorithms are not supported then it should throw a
   * CryptoException. For RSA the public key exponent must always be 0x010001. The key size of RSA
   * key pair must be 2048 bits and key size of EC key pair must be for p256 curve.
   *
   * @param alg will be KMType.RSA or KMType.EC.
   * @param privKeyBuf is the buffer to return the private key exponent in case of RSA or private
   * key in case of EC.
   * @param privKeyStart is the start offset.
   * @param privKeyMaxLength is the maximum length of this private key buffer.
   * @param pubModBuf is the buffer to return the modulus in case of RSA or public key in case of
   * EC.
   * @param pubModStart is the start of offset.
   * @param pubModMaxLength is the maximum length of this public key buffer.
   * @param lengths is the actual length of the key pair - lengths[0] should be private key and
   * lengths[1] should be public key.
   */
  void createAsymmetricKey(
      byte alg,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyMaxLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModMaxLength,
      short[] lengths);

  /**
   * Initializes the trusted confirmation operation.
   *
   * @param computedHmacKey Instance of the computed Hmac key.
   * @return instance of KMOperation.
   */
  KMOperation initTrustedConfirmationSymmetricOperation(KMComputedHmacKey computedHmacKey);
  
  /**
   * Verify that the imported key is valid. If the algorithm and/or keysize are not supported then
   * it should throw a CryptoException.
   *
   * @param alg will be KMType.AES, KMType.DES or KMType.HMAC.
   * @param keysize will be 128 or 256 for AES or DES. It can be 64 to 512 (multiple of 8) for
   * HMAC.
   * @param buf is the buffer that contains the symmetric key.
   * @param startOff is the start offset.
   * @param length of the data in the buf. This should match the keysize (in bytes).
   * @return true if the symmetric key is supported and valid.
   */
  boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff, short length);

  /**
   * Validate that the imported asymmetric key pair is valid. For RSA the public key exponent must
   * always be 0x010001. The key size of RSA key pair must be 2048 bits and key size of EC key pair
   * must be for p256 curve. If the algorithms are not supported then it should throw a
   * CryptoException.
   *
   * @param alg will be KMType.RSA or KMType.EC.
   * @param privKeyBuf is the buffer that contains the private key exponent in case of RSA or
   * private key in case of EC.
   * @param privKeyStart is the start offset.
   * @param privKeyLength is the length of this private key buffer.
   * @param pubModBuf is the buffer that contains the modulus in case of RSA or public key in case
   * of EC.
   * @param pubModStart is the start of offset.
   * @param pubModLength is the length of this public key buffer.
   * @return true if the key pair is supported and valid.
   */
  boolean importAsymmetricKey(
      byte alg,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModLength);

  /**
   * This is a oneshot operation that generates random number of desired length.
   *
   * @param num is the buffer in which random number is returned to the applet.
   * @param offset is start of the buffer.
   * @param length indicates the size of buffer and desired length of random number in bytes.
   */
  void newRandomNumber(byte[] num, short offset, short length);

  /**
   * This is a oneshot operation that adds the entropy to the entropy pool. This operation
   * corresponds to addRndEntropy command. This method may ignore the added entropy value if the SE
   * provider does not support it.
   *
   * @param num is the buffer in which entropy value is given.
   * @param offset is start of the buffer.
   * @param length length of the buffer.
   */
  void addRngEntropy(byte[] num, short offset, short length);

  /**
   * This is a oneshot operation that generates and returns back a true random number.
   *
   * @param num is the buffer in which entropy value is returned.
   * @param offset is start of the buffer.
   * @param length length of the buffer.
   */
  void getTrueRandomNumber(byte[] num, short offset, short length);

  /**
   * This is a oneshot operation that performs encryption operation using AES GCM algorithm. It
   * throws CryptoException if algorithm is not supported or if tag length is not equal to 16 or
   * nonce length is not equal to 12.
   *
   * @param aesKey is the buffer that contains 128 bit or 256 bit aes key used to encrypt.
   * @param aesKeyStart is the start in aes key buffer.
   * @param aesKeyLen is the length of aes key buffer in bytes (16 or 32 bytes).
   * @param data is the buffer that contains data to encrypt.
   * @param dataStart is the start of the data buffer.
   * @param dataLen is the length of the data buffer.
   * @param encData is the buffer of the output encrypted data.
   * @param encDataStart is the start of the encrypted data buffer.
   * @param nonce is the buffer of nonce.
   * @param nonceStart is the start of the nonce buffer.
   * @param nonceLen is the length of the nonce buffer.
   * @param authData is the authentication data buffer.
   * @param authDataStart is the start of the authentication buffer.
   * @param authDataLen is the length of the authentication buffer.
   * @param authTag is the buffer to output authentication tag.
   * @param authTagStart is the start of the buffer.
   * @param authTagLen is the length of the buffer.
   * @return length of the encrypted data.
   */
  short aesGCMEncrypt(
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
      byte[] data,
      short dataStart,
      short dataLen,
      byte[] encData,
      short encDataStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen);

  /**
   * This is a oneshot operation that performs decryption operation using AES GCM algorithm. It
   * throws CryptoException if algorithm is not supported.
   *
   * @param aesKey is the buffer that contains 128 bit or 256 bit aes key used to encrypt.
   * @param aesKeyStart is the start in aes key buffer.
   * @param aesKeyLen is the length of aes key buffer in bytes (16 or 32 bytes).
   * @param encData is the buffer of the input encrypted data.
   * @param encDataStart is the start of the encrypted data buffer.
   * @param encDataLen is the length of the data buffer.
   * @param data is the buffer that contains output decrypted data.
   * @param dataStart is the start of the data buffer.
   * @param nonce is the buffer of nonce.
   * @param nonceStart is the start of the nonce buffer.
   * @param nonceLen is the length of the nonce buffer.
   * @param authData is the authentication data buffer.
   * @param authDataStart is the start of the authentication buffer.
   * @param authDataLen is the length of the authentication buffer.
   * @param authTag is the buffer to output authentication tag.
   * @param authTagStart is the start of the buffer.
   * @param authTagLen is the length of the buffer.
   * @return true if the authentication is valid.
   */
  boolean aesGCMDecrypt(
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
      byte[] encData,
      short encDataStart,
      short encDataLen,
      byte[] data,
      short dataStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen);

  /**
   * This is a oneshot operation that performs key derivation function using cmac kdf (CKDF) as
   * defined in android keymaster hal definition.
   *
   * @param hmacKey of pre-shared key.
   * @param label is the label to be used for ckdf.
   * @param labelStart is the start of label.
   * @param labelLen is the length of the label.
   * @param context is the context to be used for ckdf.
   * @param contextStart is the start of the context
   * @param contextLength is the length of the context
   * @param key is the output buffer to return the derived key
   * @param keyStart is the start of the output buffer.
   * @return length of the derived key buffer in bytes.
   */
  short cmacKDF(
      KMPreSharedKey hmacKey,
      byte[] label,
      short labelStart,
      short labelLen,
      byte[] context,
      short contextStart,
      short contextLength,
      byte[] key,
      short keyStart);

  /**
   * This is a oneshot operation that signs the data using hmac algorithm.
   *
   * @param keyBuf is the buffer with hmac key.
   * @param keyStart is the start of the buffer.
   * @param keyLength is the length of the buffer which will be in bytes from 8 to 64.
   * @param data is the buffer containing data to be signed.
   * @param dataStart is the start of the data.
   * @param dataLength is the length of the data.
   * @param signature is the output signature buffer
   * @param signatureStart is the start of the signature
   * @return length of the signature buffer in bytes.
   */
  short hmacSign(
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] signature,
      short signatureStart);
  
  /**
   * This is a oneshot operation that signs the data using hmac algorithm.
   *
   * @param hmacKey is the KMHmacKey.
   * @param data is the buffer containing data to be signed.
   * @param dataStart is the start of the data.
   * @param dataLength is the length of the data.
   * @param signature is the output signature buffer
   * @param signatureStart is the start of the signature
   * @return length of the signature buffer in bytes.
   */
  short hmacSign(
	  Object hmacKey,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] signature,
      short signatureStart);

  /**
   * This is a oneshot operation that signs the data using hmac algorithm. This is used to derive
   * the key, which is used to encrypt the keyblob.
   *
   * @param masterkey of masterkey.
   * @param data is the buffer containing data to be signed.
   * @param dataStart is the start of the data.
   * @param dataLength is the length of the data.
   * @param signature is the output signature buffer
   * @param signatureStart is the start of the signature
   * @return length of the signature buffer in bytes.
   */
  short hmacKDF(
      KMMasterKey masterkey,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] signature,
      short signatureStart);

  /**
   * This is a oneshot operation that verifies the signature using hmac algorithm.
   *
   * @param keyBuf is the buffer with hmac key.
   * @param keyStart is the start of the buffer.
   * @param keyLength is the length of the buffer which will be in bytes from 8 to 64.
   * @param data is the buffer containing data.
   * @param dataStart is the start of the data.
   * @param dataLength is the length of the data.
   * @param signature is the signature buffer.
   * @param signatureStart is the start of the signature buffer.
   * @param signatureLen is the length of the signature buffer in bytes.
   * @return true if the signature matches.
   */
  boolean hmacVerify(
      KMComputedHmacKey hmacKey,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] signature,
      short signatureStart,
      short signatureLen);

  /**
   * This is a oneshot operation that decrypts the data using RSA algorithm with oaep256 padding.
   * The public exponent is always 0x010001. It throws CryptoException if OAEP encoding validation
   * fails.
   *
   * @param privExp is the private exponent (2048 bit) buffer.
   * @param privExpStart is the start of the private exponent buffer.
   * @param privExpLength is the length of the private exponent buffer in bytes.
   * @param modBuffer is the modulus (2048 bit) buffer.
   * @param modOff is the start of the modulus buffer.
   * @param modLength is the length of the modulus buffer in bytes.
   * @param inputDataBuf is the buffer of the input data.
   * @param inputDataStart is the start of the input data buffer.
   * @param inputDataLength is the length of the input data buffer in bytes.
   * @param outputDataBuf is the output buffer that contains the decrypted data.
   * @param outputDataStart is the start of the output data buffer.
   * @return length of the decrypted data.
   */
  short rsaDecipherOAEP256(
      byte[] privExp,
      short privExpStart,
      short privExpLength,
      byte[] modBuffer,
      short modOff,
      short modLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart);

  /**
   * This is a oneshot operation that signs the data using EC private key.
   *
   * @param ecPrivKey of KMAttestationKey.
   * @param inputDataBuf is the buffer of the input data.
   * @param inputDataStart is the start of the input data buffer.
   * @param inputDataLength is the length of the inpur data buffer in bytes.
   * @param outputDataBuf is the output buffer that contains the signature.
   * @param outputDataStart is the start of the output data buffer.
   * @return length of the decrypted data.
   */
  short ecSign256(
      KMAttestationKey ecPrivKey,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart);

  /**
   * Implementation of HKDF as per RFC5869 https://datatracker.ietf.org/doc/html/rfc5869#section-2
   *
   * @param ikm is the buffer containing input key material.
   * @param ikmOff is the start of the input key.
   * @param ikmLen is the length of the input key.
   * @param salt is the buffer containing the salt.
   * @param saltOff is the start of the salt buffer.
   * @param saltLen is the length of the salt buffer.
   * @param info is the buffer containing the application specific information
   * @param infoOff is the start of the info buffer.
   * @param infoLen is the length of the info buffer.
   * @param out is the output buffer.
   * @param outOff is the start of the output buffer.
   * @param outLen is the length of the expected out buffer.
   * @return Length of the out buffer which is outLen.
   */
  short hkdf(
      byte[] ikm,
      short ikmOff,
      short ikmLen,
      byte[] salt,
      short saltOff,
      short saltLen,
      byte[] info,
      short infoOff,
      short infoLen,
      byte[] out,
      short outOff,
      short outLen);

  /**
   * This function performs ECDH key agreement and generates a secret.
   *
   * @param privKey is the buffer containing the private key from first party.
   * @param privKeyOff is the offset of the private key buffer.
   * @param privKeyLen is the length of the private key buffer.
   * @param publicKey is the buffer containing the public key from second party.
   * @param publicKeyOff is the offset of the public key buffer.
   * @param publicKeyLen is the length of the public key buffer.
   * @param secret is the output buffer.
   * @param secretOff is the offset of the output buffer.
   * @return The length of the secret.
   */
  short ecdhKeyAgreement(
      byte[] privKey,
      short privKeyOff,
      short privKeyLen,
      byte[] publicKey,
      short publicKeyOff,
      short publicKeyLen,
      byte[] secret,
      short secretOff);

  /**
   * This is a oneshort operation that verifies the data using EC public key
   *
   * @param pubKey is the public key buffer.
   * @param pubKeyOffset is the start of the public key buffer.
   * @param pubKeyLen is the length of the public key.
   * @param inputDataBuf is the buffer of the input data.
   * @param inputDataStart is the start of the input data buffer.
   * @param inputDataLength is the length of the input data buffer in bytes.
   * @param signatureDataBuf is the buffer the signature input data.
   * @param signatureDataStart is the start of the signature input data.
   * @param signatureDataLen is the length of the signature input data.
   * @return true if verification is successful, otherwise false.
   */
  boolean ecVerify256(
      byte[] pubKey,
      short pubKeyOffset,
      short pubKeyLen,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] signatureDataBuf,
      short signatureDataStart,
      short signatureDataLen);


  short ecSign256(byte[] secret, short secretStart, short secretLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart);

  short rsaSign256Pkcs1(
      byte[] secret,
      short secretStart,
      short secretLength,
      byte[] modBuf,
      short modStart,
      short modLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart);

  /**
   * This creates a persistent operation for signing, verify, encryption and decryption using HMAC,
   * AES and DES algorithms when keymaster hal's beginOperation function is executed. The
   * KMOperation instance can be reclaimed by the seProvider when KMOperation is finished or
   * aborted. It throws CryptoException if algorithm is not supported.
   *
   * @param purpose is KMType.ENCRYPT or KMType.DECRYPT for AES and DES algorithm. It will be
   * KMType.SIGN and KMType.VERIFY for HMAC algorithm
   * @param alg is KMType.HMAC, KMType.AES or KMType.DES.
   * @param digest is KMType.SHA2_256 in case of HMAC else it will be KMType.DIGEST_NONE.
   * @param padding is KMType.PADDING_NONE or KMType.PKCS7 (in case of AES and DES).
   * @param blockMode is KMType.CTR, KMType.GCM. KMType.CBC or KMType.ECB for AES or DES else it is
   * 0.
   * @param keyBuf is aes, des or hmac key buffer.
   * @param keyStart is the start of the key buffer.
   * @param keyLength is the length of the key buffer.
   * @param ivBuf is the iv buffer (in case on AES and DES algorithm without ECB mode)
   * @param ivStart is the start of the iv buffer.
   * @param ivLength is the length of the iv buffer. It will be zero in case of HMAC and AES/DES
   * with ECB mode.
   * @param macLength is the mac length in case of signing operation for hmac algorithm.
   * @return KMOperation instance.
   */
  KMOperation initSymmetricOperation(
      byte purpose,
      byte alg,
      byte digest,
      byte padding,
      byte blockMode,
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] ivBuf,
      short ivStart,
      short ivLength,
      short macLength);

  /**
   * This creates a persistent operation for signing, verify, encryption and decryption using HMAC,
   * AES and DES algorithms when keymaster hal's beginOperation function is executed. The
   * KMOperation instance can be reclaimed by the seProvider when KMOperation is finished or
   * aborted. It throws CryptoException if algorithm is not supported.
   *
   * @param purpose is KMType.ENCRYPT or KMType.DECRYPT for AES and DES algorithm. It will be
   * KMType.SIGN and KMType.VERIFY for HMAC algorithm
   * @param alg is KMType.HMAC, KMType.AES or KMType.DES.
   * @param digest is KMType.SHA2_256 in case of HMAC else it will be KMType.DIGEST_NONE.
   * @param padding is KMType.PADDING_NONE or KMType.PKCS7 (in case of AES and DES).
   * @param blockMode is KMType.CTR, KMType.GCM. KMType.CBC or KMType.ECB for AES or DES else it is
   * 0.
   * @param key is a key object.
   * @param interfaceType defines the type of key in the key object.
   * @param ivBuf is the iv buffer (in case on AES and DES algorithm without ECB mode)
   * @param ivStart is the start of the iv buffer.
   * @param ivLength is the length of the iv buffer. It will be zero in case of HMAC and AES/DES
   * with ECB mode.
   * @param macLength is the mac length in case of signing operation for hmac algorithm.
   * @param oneShot if true, creates oneshot operation.
   * @return KMOperation instance.
   */
  KMOperation initSymmetricOperation(
      byte purpose,
      byte alg,
      byte digest,
      byte padding,
      byte blockMode,
      Object key,
      byte interfaceType,
      byte[] ivBuf,
      short ivStart,
      short ivLength,
      short macLength,
      boolean oneShot);
  
  /**
   * This creates a persistent operation for signing, verify, encryption and decryption using RSA
   * and EC algorithms when keymaster hal's beginOperation function is executed. For RSA the public
   * exponent is always 0x0100101. For EC the curve is always p256. The KMOperation instance can be
   * reclaimed by the seProvider when KMOperation is finished or aborted. It throws CryptoException
   * if algorithm is not supported.
   *
   * @param purpose is KMType.ENCRYPT or KMType.DECRYPT for RSA. It will be * KMType.SIGN and
   * KMType.VERIFY for RSA and EC algorithms.
   * @param alg is KMType.RSA or KMType.EC algorithms.
   * @param padding is KMType.PADDING_NONE or KMType.RSA_OAEP, KMType.RSA_PKCS1_1_5_ENCRYPT,
   * KMType.RSA_PKCS1_1_5_SIGN or KMType.RSA_PSS.
   * @param digest is KMType.DIGEST_NONE or KMType.SHA2_256.
   * @param mgfDigest is the MGF digest.
   * @param privKeyBuf is the private key in case of EC or private key exponent is case of RSA.
   * @param privKeyStart is the start of the private key.
   * @param privKeyLength is the length of the private key.
   * @param pubModBuf is the modulus (in case of RSA) or public key (in case of EC).
   * @param pubModStart is the start of the modulus.
   * @param pubModLength is the length of the modulus.
   * @return KMOperation instance that can be executed.
   */
  KMOperation initAsymmetricOperation(
      byte purpose,
      byte alg,
      byte padding,
      byte digest,
      byte mgfDigest,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModLength);

  /**
   * This function tells if applet is upgrading or not.
   *
   * @return true if upgrading, otherwise false.
   */
  boolean isUpgrading();

  /**
   * This function generates an AES Key of keySizeBits, which is used as an master key. This
   * generated key is maintained by the SEProvider. This function should be called only once at the
   * time of installation.
   *
   * @param instance of the masterkey.
   * @param keySizeBits key size in bits.
   * @return An instance of KMMasterKey.
   */
  KMMasterKey createMasterKey(KMMasterKey masterKey, short keySizeBits);

  /**
   * This function creates an HMACKey and initializes the key with the provided input key data.
   *
   * @param keyData buffer containing the key data.
   * @param offset start of the buffer.
   * @param length length of the buffer.
   * @return An instance of the KMComputedHmacKey.
   */
  KMComputedHmacKey createComputedHmacKey(KMComputedHmacKey computedHmacKey, byte[] keyData, short offset, short length);

  /**
   * Returns true if factory provisioned attestation key is supported.
   */
  boolean isAttestationKeyProvisioned();

  /**
   * Returns algorithm type of the attestation key. It can be KMType.EC or KMType.RSA if the
   * attestation key is provisioned in the factory.
   */
  short getAttestationKeyAlgorithm();

  /**
   * This function creates an ECKey and initializes the ECPrivateKey with the provided input key
   * data. The initialized Key is maintained by the SEProvider. This function should be called only
   * while provisioning the attestation key.
   *
   * @param key instance of the KMAttestationKey.
   * @param keyData buffer containing the ec private key.
   * @param offset start of the buffer.
   * @param length length of the buffer.
   * @return An instance of KMAttestationKey.
   */
  KMAttestationKey createAttestationKey(KMAttestationKey key,
      byte[] keyData, short offset, short length);
  
  /**
   * This is a one-shot operation the does digest of the input mesage.
   *
   * @param inBuff input buffer to be digested.
   * @param inOffset start offset of the input buffer.
   * @param inLength length of the input buffer.
   * @param outBuff is the output buffer that contains the digested data.
   * @param outOffset start offset of the digested output buffer.
   * @return length of the digested data.
   */
  short messageDigest256(byte[] inBuff, short inOffset, short inLength, byte[] outBuff,
      short outOffset);
  
  /**
   * This function generates a HMAC key from the provided key buffers.
   *
   * @param presharedKey instance of the presharedkey.
   * @param key buffer containing the key data.
   * @param offset start offset of the buffer.
   * @param length is the length of the key.
   * @return instance of KMPresharedKey.
   */
  KMPreSharedKey createPreSharedKey(KMPreSharedKey presharedKey, byte[] key, short offset,
      short length);
  
  /**
   * This function saves the key objects while upgrade.
   *
   * @param element instance of the Element class where the objects to be stored.
   * @param interfaceType the type interface of the parent object.
   * @param object instance of the object to be saved.
   */
  void onSave(Element element, byte interfaceType, Object object);
  
  /**
   * This function restores the the object from element instance.
   * 
   * @param element instance of the Element class.
   * @return restored object.
   */
  Object onRestore(Element element);
  
  /**
   * This function returns the count of the primitive bytes required to
   * be stored by the implementation of the interface type.
   *
   * @param interfaceType type interface of the parent object.
   * @return count of the primitive bytes.
   */
  short getBackupPrimitiveByteCount(byte interfaceType);

  /**
   * This function returns the object count required to be stored by the
   * implementation of the interface type.
   *
   * @param interfaceType type interface of the parent object.
   * @return count of the objects.
   */
  short getBackupObjectCount(byte interfaceType);
}
