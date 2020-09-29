package com.android.javacard.keymaster;

/**
 * KMSEProvider is facade to use SE specific methods. The main intention of this interface is to
 * abstract the cipher, signature and backup and restore related functions. The instance of this
 * interface is created by the singleton KMSEProviderImpl class for each provider. At a time there
 * can be only one provider in the applet package.
 */
public interface KMSEProvider {
  /**
   * Create a symmetric key instance. If the algorithm and/or keysize are not supported then it
   * should throw a CryptoException.
   *
   * @param alg will be KMType.AES, KMType.DES or KMType.HMAC.
   * @param keysize will be 128 or 256 for AES or DES. It can be 64 to 512 (multiple of 8) for HMAC.
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
   *     key in case of EC.
   * @param privKeyStart is the start offset.
   * @param privKeyMaxLength is the maximum length of this private key buffer.
   * @param pubModBuf is the buffer to return the modulus in case of RSA or public key in case of
   *     EC.
   * @param pubModStart is the start of offset.
   * @param pubModMaxLength is the maximum length of this public key buffer.
   * @param lengths is the actual length of the key pair - lengths[0] should be private key and
   *     lengths[1] should be public key.
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
   * Verify that the imported key is valid.
   *
   * @param alg will be KMType.AES, KMType.DES or KMType.HMAC.
   * @param keysize will be 128 or 256 for AES or DES. It can be 64 to 512 (multiple of 8) for HMAC.
   * @param buf is the buffer in which key has to be returned
   * @param startOff is the start offset.
   * @param length of the data in the buf. This should match the keysize (in bytes).
   * @return true if the symmetric key is supported and valid.
   */
  boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff, short length);

  /**
   * Validate that the imported asymmetric key pair is valid. For RSA the public key exponent must
   * always be 0x010001. The key size of RSA key pair must be 2048 bits and key size of EC key pair
   * must be for p256 curve.
   *
   * @param alg will be KMType.RSA or KMType.EC.
   * @param privKeyBuf is the buffer to return the private key exponent in case of RSA or private
   *     key in case of EC.
   * @param privKeyStart is the start offset.
   * @param privKeyLength is the length of this private key buffer.
   * @param pubModBuf is the buffer to return the modulus in case of RSA or public key in case of
   *     EC.
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
   * @param num is the buffer in which random number is returned to applet.
   * @param offset is start of the buffer.
   * @param length indicates the size of buffer and desired length of random number in bytes.
   */
  void newRandomNumber(byte[] num, short offset, short length);

  /**
   * This is a oneshot operation that adds the entropy to the entroy pool. This operation
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
   * @param num is the buffer in which entropy value is given.
   * @param offset is start of the buffer.
   * @param length length of the buffer.
   */
  void getTrueRandomNumber(byte[] num, short offset, short length);

  /**
   * This is a oneshot operation that performs encryption operation using AES GCM algorithm.
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
   * This is a oneshot operation that performs decryption operation using AES GCM algorithm.
   *
   * @param aesKey is the buffer that contains 128 bit or 256 bit aes key used to encrypt.
   * @param aesKeyStart is the start in aes key buffer.
   * @param aesKeyLen is the length of aes key buffer in bytes (16 or 32 bytes).
   * @param encData is the buffer of the input encrypted data.
   * @param encDataStart is the start of the encrypted data buffer.
   * @param encDataLen is the length of the data buffer.
   * @param data is the buffer that contains output data to encrypt.
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
   * This is a oneshot operation that performs signing using AES CCM algorithm.
   *
   * @param data is the input data buffer.
   * @param dataStart is the start of the buffer.
   * @param dataLen is the length of the input data
   * @param aesKey is the aesKey buffer either 128 bit or 256 bit aes key.
   * @param aesKeyStart is the start of the aes key.
   * @param aesKeyLen is the length of the aes key buffer in bytes.
   * @param signature is the output signature buffer.
   * @param signatureStart is the start of the signature buffer.
   * @return length of the signature buffer.
   */
  short aesCCMSign(
      byte[] data,
      short dataStart,
      short dataLen,
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
      byte[] signature,
      short signatureStart);

  /**
   * This is a oneshot operation that performs key derivation function using cmac kdf (CKDF) as
   * defined in android keymaster hal definition.
   *
   * @param aesKey is the key to use for ckdf.
   * @param aesKeyStart is the start of the aes key buffer.
   * @param aesKeyLen is the length of the aes key buffer.
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
  short cmacKdf(
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
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
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] signature,
      short signatureStart,
      short signatureLen);

  /**
   * This is a oneshot operation that decrypts the data using RSA algorithm with oaep256 padding.
   * The public exponent is always 0x010001.
   *
   * @param privExp is the private exponent (2048 bit) buffer.
   * @param privExpStart is the start of the private exponent buffer.
   * @param privExpLength is the length of the private exponent buffer in bytes.
   * @param modBuffer is the modulus (2048 bit) buffer.
   * @param modOff is the start of the modulus buffer.
   * @param modLength is the length of the modulus buffer in bytes.
   * @param inputDataBuf is the buffer of the input data.
   * @param inputDataStart is the start of the input data buffer.
   * @param inputDataLength is the length of the inpur data buffer in bytes.
   * @param outputDataBuf is the buffer of the decrypted data buffer.
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
   * This is a oneshot operation that decrypts the data using RSA algorithm with oaep256 padding.
   * The public exponent is always 0x010001.
   *
   * @param privExp is the private exponent (2048 bit) buffer.
   * @param privExpStart is the start of the private exponent buffer.
   * @param privExpLength is the length of the private exponent buffer in bytes.
   * @param modBuffer is the modulus (2048 bit) buffer.
   * @param modOff is the start of the modulus buffer.
   * @param modLength is the length of the modulus buffer in bytes.
   * @param inputDataBuf is the buffer of the input data.
   * @param inputDataStart is the start of the input data buffer.
   * @param inputDataLength is the length of the inpur data buffer in bytes.
   * @param outputDataBuf is the buffer of the decrypted data buffer.
   * @param outputDataStart is the start of the output data buffer.
   * @return length of the decrypted data.
   */
  short rsaSignPKCS1256(
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
   * This creates a persistent operation for signing, verify, encryption and decryption using HMAC,
   * AES and DES algorithms when keymaster hal's beginOperation function is executed. The
   * KMOperation instance can be reclaimed by the seProvider when KMOperation is finished or
   * aborted.
   *
   * @param purpose is KMType.ENCRYPT or KMType.DECRYPT for AES and DES algorithm. It will be
   *     KMType.SIGN and KMType.VERIFY for HMAC algorithm
   * @param alg is KMType.HMAC, KMType.AES or KMType.DES.
   * @param digest is KMType.SHA2_256 in case of HMAC else it will be KMType.DIGEST_NONE.
   * @param padding is KMType.PADDING_NONE or KMType.PKCS7 (in case of AES and DES).
   * @param blockMode is KMType.CTR, KMType.GCM. KMType.CBC or KMType.ECB for AES or DES else it is
   *     0.
   * @param keyBuf is aes, des or hmac key buffer.
   * @param keyStart is the start of the key buffer.
   * @param keyLength is the length of the key buffer.
   * @param ivBuf is the iv buffer (in case on AES and DES algorithm without ECB mode)
   * @param ivStart is the start of the iv buffer.
   * @param ivLength is the length of the iv buffer. It will be zero in case of HMAC and AES/DES
   *     with ECB mode.
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
   * This creates a persistent operation for signing, verify, encryption and decryption using RSA
   * and EC algorithms when keymaster hal's beginOperation function is executed. For RSA the public
   * exponent is always 0x0100101. For EC the curve is always p256. The KMOperation instance can be
   * reclaimed by the seProvider when KMOperation is finished or aborted.
   *
   * @param purpose is KMType.ENCRYPT or KMType.DECRYPT for RSA. It will be * KMType.SIGN and
   *     KMType.VERIFY for RSA and EC algorithms.
   * @param alg is KMType.RSA or KMType.EC algorithms.
   * @param padding is KMType.PADDING_NONE or KMType.RSA_OAEP, KMType.RSA_PKCS1_1_5_ENCRYPT,
   *     KMType.RSA_PKCS1_1_5_SIGN or KMType.RSA_PSS.
   * @param digest is KMType.DIGEST_NONE or KMType.SHA2_256.
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
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModLength);

  /**
   * This operation creates the empty instance of KMAttestationCert for rsa or ec public key
   * attestation certificate. It corresponds to attestKEy command from keymaster hal specifications.
   * The attestation certificate implementation will comply keymaster hal specifications.
   *
   * @param rsaCert if true indicates that certificate will attest a rsa public key else if false it
   *     is for ec public key.
   * @return An empty instance of KMAttestationCert implementation.
   */
  KMAttestationCert getAttestationCert(boolean rsaCert);

  /**
   * This operation indicates whether SE Provider supports backup and restore functionality required
   * for upgrading the applet.
   *
   * @return true if backup and restore is supported.
   */
  boolean isBackupRestoreSupported();

  /**
   * This operation passes the data that needs to be backup to SE Provider. The exact mechanism to
   * backup the data is SE provider implementation specific.
   *
   * @param buf is the data buffer.
   * @param start is the start of the data.
   * @param len is the length of the data.
   */
  void backup(byte[] buf, short start, short len);

  /**
   * This operation retrieves the backed up data from SE Provider.
   *
   * @param buf is the data buffer.
   * @param start is the start of the data.
   * @return the length of the data buffer in bytes.
   */
  short restore(byte[] buf, short start);
}
