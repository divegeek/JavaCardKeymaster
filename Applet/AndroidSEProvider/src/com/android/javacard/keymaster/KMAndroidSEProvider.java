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
package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.MessageDigest;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

public class KMAndroidSEProvider implements KMSEProvider {

  // static final variables
  // --------------------------------------------------------------
  // P-256 Curve Parameters
  static final byte[] secp256r1_P = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF};

  static final byte[] secp256r1_A = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFC};

  static final byte[] secp256r1_B = {
      (byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
      (byte) 0x3A, (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB,
      (byte) 0xBD, (byte) 0x55, (byte) 0x76, (byte) 0x98, (byte) 0x86,
      (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0,
      (byte) 0xCC, (byte) 0x53, (byte) 0xB0, (byte) 0xF6, (byte) 0x3B,
      (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27, (byte) 0xD2,
      (byte) 0x60, (byte) 0x4B};

  static final byte[] secp256r1_S = {
      (byte) 0xC4, (byte) 0x9D, (byte) 0x36, (byte) 0x08, (byte) 0x86,
      (byte) 0xE7, (byte) 0x04, (byte) 0x93, (byte) 0x6A, (byte) 0x66,
      (byte) 0x78, (byte) 0xE1, (byte) 0x13, (byte) 0x9D, (byte) 0x26,
      (byte) 0xB7, (byte) 0x81, (byte) 0x9F, (byte) 0x7E, (byte) 0x90};

  // Uncompressed form
  static final byte[] secp256r1_UCG = {
      (byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
      (byte) 0xE1, (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8,
      (byte) 0xBC, (byte) 0xE6, (byte) 0xE5, (byte) 0x63, (byte) 0xA4,
      (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D,
      (byte) 0x81, (byte) 0x2D, (byte) 0xEB, (byte) 0x33, (byte) 0xA0,
      (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45, (byte) 0xD8,
      (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3,
      (byte) 0x42, (byte) 0xE2, (byte) 0xFE, (byte) 0x1A, (byte) 0x7F,
      (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
      (byte) 0x7C, (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B,
      (byte) 0xCE, (byte) 0x33, (byte) 0x57, (byte) 0x6B, (byte) 0x31,
      (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40,
      (byte) 0x68, (byte) 0x37, (byte) 0xBF, (byte) 0x51, (byte) 0xF5};

  static final byte[] secp256r1_N = {
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
      (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
      (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD,
      (byte) 0xA7, (byte) 0x17, (byte) 0x9E, (byte) 0x84, (byte) 0xF3,
      (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC, (byte) 0x63,
      (byte) 0x25, (byte) 0x51};
  static final short secp256r1_H = 1;
  // --------------------------------------------------------------
  public static final short AES_GCM_TAG_LENGTH = 16;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final byte KEYSIZE_128_OFFSET = 0x00;
  public static final byte KEYSIZE_256_OFFSET = 0x01;
  public static final short TMP_ARRAY_SIZE = 300;
  private static final short RSA_KEY_SIZE = 256;
  private static final short MAX_OPERATIONS = 4;
  private static final short HMAC_MAX_OPERATIONS = 8;
  private static final short COMPUTED_HMAC_KEY_SIZE = 32;
  public static final short INVALID_DATA_VERSION = 0x7FFF;
  
  private static final short CERT_CHAIN_OFFSET = 0;
  private static final short CERT_ISSUER_OFFSET = KMConfigurations.CERT_CHAIN_MAX_SIZE;
  private static final short CERT_EXPIRY_OFFSET = 
      (short) (CERT_ISSUER_OFFSET + KMConfigurations.CERT_ISSUER_MAX_SIZE);

  public static final short MAX_OPERATION_INSTANCES = 4;
  private static final short HMAC_MAX_OPERATION_INSTANCES = 8;
  
  public static final byte AES_128 = 0x04;
  public static final byte AES_256 = 0x05;
  //Resource type constants
  public static final byte RESOURCE_TYPE_CRYPTO = 0x00;
  public static final byte RESOURCE_TYPE_KEY = 0x01;
  public static final byte EC_PUB_KEY_SIZE = 65;
  
  final byte[] KEY_ALGS = {
	 AES_128,
	 AES_256,
         KMType.DES,
         KMType.RSA,
         KMType.EC,
         KMType.HMAC};

  private static final byte[] CIPHER_ALGS = {
      Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
      Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
      Cipher.ALG_DES_CBC_NOPAD,
      Cipher.ALG_DES_ECB_NOPAD,
      Cipher.ALG_AES_CTR,
      Cipher.ALG_RSA_PKCS1,
      KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1,
      Cipher.ALG_RSA_NOPAD,
      AEADCipher.ALG_AES_GCM};

  private static final byte[] SIG_ALGS = {
      Signature.ALG_RSA_SHA_256_PKCS1,
      Signature.ALG_RSA_SHA_256_PKCS1_PSS,
      Signature.ALG_ECDSA_SHA_256,
      Signature.ALG_HMAC_SHA_256,
      KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD,
      KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST,
      KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST};

  // [L] 256 bits - hardcoded 32 bits as per
  // reference impl in keymaster.
  private static final byte[] CMAC_KDF_CONSTANT_L = {
      0, 0, 1, 0
  };
  private static final byte[] CMAC_KDF_CONSTANT_ZERO = {
      0
  };
  // AESKey
  private AESKey aesKeys[];
  // DES3Key
  private DESKey triDesKey;
  // HMACKey
  private HMACKey hmacKey;
  // RSA Key Pair
  private KeyPair rsaKeyPair;
  // EC Key Pair.
  private KeyPair ecKeyPair;
  // Temporary array.
  public byte[] tmpArray;
  // This is used for internal encryption/decryption operations.
  private static AEADCipher aesGcmCipher;
  // Cipher pool
  private Object[] cipherPool;
  // Signature pool
  private Object[] sigPool;
  // KMOperationImpl pool
  private Object[] operationPool;
  
 //Hmac signer pool which is used to support TRUSTED_CONFIRMATION_REQUIRED tag.
 private Object[] hmacSignOperationPool;
  
  private Object[] keysPool;
  
  private Signature kdf;

  private Signature hmacSignature;
  //For ImportwrappedKey operations.
  private KMRsaOAEPEncoding rsaOaepDecipher;

  // Entropy
  private RandomData rng;
  //For storing root certificate and intermediate certificates.
  private byte[] provisionData;
  private KMAESKey masterKey;
  private KMECPrivateKey attestationKey;
  private KMHmacKey preSharedKey;
  private KMHmacKey computedHmacKey;
  private byte[] oemRootPublicKey;

  private static KMAndroidSEProvider androidSEProvider = null;

  public static KMAndroidSEProvider getInstance() {
    return androidSEProvider;
  }

  public KMAndroidSEProvider() {
    // Re-usable AES,DES and HMAC keys in persisted memory.
    aesKeys = new AESKey[2];
    aesKeys[KEYSIZE_128_OFFSET] = (AESKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
    aesKeys[KEYSIZE_256_OFFSET] = (AESKey) KeyBuilder.buildKey(
        KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_256, false);
    triDesKey = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET,
        KeyBuilder.LENGTH_DES3_3KEY, false);
    hmacKey = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, (short) 512,
        false);
    rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    initECKey(ecKeyPair);

    // Re-usable cipher and signature instances
    cipherPool = new Object[(short) (CIPHER_ALGS.length * 4)];
    // Extra 4 algorithms are used to support TRUSTED_CONFIRMATION_REQUIRED feature.
    sigPool = new Object[(short) ((SIG_ALGS.length * 4) + 4)];
    operationPool = new Object[MAX_OPERATION_INSTANCES];
    hmacSignOperationPool = new Object[MAX_OPERATION_INSTANCES];
    // Reserve (KEY_ALGS.length * 4) + 4) size of key pool
    // Extra 4 keys for TRUSTED_CONFIRMATION_REQUIRED feature.
    keysPool = new Object[(short) ((KEY_ALGS.length * 4) + 4)];
    
    // Creates an instance of each cipher algorithm once.
    initializeCipherPool();
    // Creates an instance of each signature algorithm once.
    initializeSigPool();
    initializeOperationPool();
    initializeHmacSignOperationPool();
    initializeKeysPool();
    //RsaOAEP Decipher
    rsaOaepDecipher = new KMRsaOAEPEncoding(KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1);

    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

    // Temporary transient array created to use locally inside functions.
    tmpArray = JCSystem.makeTransientByteArray(TMP_ARRAY_SIZE,
        JCSystem.CLEAR_ON_DESELECT);

    // Random number generator initialisation.
    rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    //Allocate buffer for certificate chain.
    if (!isUpgrading()) {
      // First 2 bytes is reserved for length for all the 3 buffers.
      short totalLen = (short) (6 +  KMConfigurations.CERT_CHAIN_MAX_SIZE +
          KMConfigurations.CERT_ISSUER_MAX_SIZE + KMConfigurations.CERT_EXPIRY_MAX_SIZE);
      provisionData = new byte[totalLen];
      oemRootPublicKey = new byte[EC_PUB_KEY_SIZE];
      
      // Initialize attestationKey and preShared key with zeros.
      Util.arrayFillNonAtomic(tmpArray, (short) 0, TMP_ARRAY_SIZE, (byte) 0);
      // Create attestation key of P-256 curve.
      createAttestationKey(tmpArray, (short)0, (short) 32);
      // Pre-shared secret key length is 32 bytes.
      createPresharedKey(tmpArray, (short)0, (short) 32);
      // Initialize the Computed Hmac Key object.
      createComputedHmacKey(tmpArray, (short)0, (short) 32);
    }
    androidSEProvider = this;
  }

  public void clean() {
    Util.arrayFillNonAtomic(tmpArray, (short) 0, (short) 256, (byte) 0);
  }

  private void initECKey(KeyPair ecKeyPair) {
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();
    pubkey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    pubkey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    pubkey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    pubkey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    pubkey.setK(secp256r1_H);
    pubkey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);

    privKey.setFieldFP(secp256r1_P, (short) 0, (short) secp256r1_P.length);
    privKey.setA(secp256r1_A, (short) 0, (short) secp256r1_A.length);
    privKey.setB(secp256r1_B, (short) 0, (short) secp256r1_B.length);
    privKey.setG(secp256r1_UCG, (short) 0, (short) secp256r1_UCG.length);
    privKey.setK(secp256r1_H);
    privKey.setR(secp256r1_N, (short) 0, (short) secp256r1_N.length);
  }

  private boolean isCipherAlgorithm(byte alg) {
    short index = 0;
    while (index < CIPHER_ALGS.length) {
      if (CIPHER_ALGS[index++] == alg) {
        return true;
      }
    }
    return false;
  }

  private boolean isSignerAlgorithm(byte alg) {
    short index = 0;
    while (index < SIG_ALGS.length) {
      if (SIG_ALGS[index++] == alg) {
        return true;
      }
    }
    return false;
  }

  private void initializeOperationPool() {
    short index = 0;
    while (index < MAX_OPERATION_INSTANCES) {
      operationPool[index] = new KMOperationImpl();
      index++;
    }
  }

  private void initializeHmacSignOperationPool() {
    short index = 0;
    while (index < MAX_OPERATION_INSTANCES) {
      hmacSignOperationPool[index] = new KMOperationImpl();
      index++;
    }
  }

  // Create a signature instance of each algorithm once.
  private void initializeSigPool() {
    short index = 0;
    while (index < SIG_ALGS.length) {
      sigPool[index] = getSignatureInstance(SIG_ALGS[index]);
      index++;
    }
  }

  private void initializeKeysPool() {
    short index = 0;
    while (index < KEY_ALGS.length) {
      keysPool[index] = createKeyObjectInstance(KEY_ALGS[index]);
      index++;
    }
  }

  private Signature getSignatureInstance(byte alg) {
    if (KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD == alg
        || KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST == alg) {
      return new KMRsa2048NoDigestSignature(alg);
    } else if (KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST == alg) {
      return new KMEcdsa256NoDigestSignature(alg);
    } else {
      return Signature.getInstance(alg, false);
    }
  }

  private Cipher getCipherInstance(byte alg) {
    if (KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1 == alg) {
      return new KMRsaOAEPEncoding(alg);
    } else {
      return Cipher.getInstance(alg, false);
    }
  }

  // Create a cipher instance of each algorithm once.
  private void initializeCipherPool() {
    short index = 0;
    while (index < CIPHER_ALGS.length) {
      cipherPool[index] = getCipherInstance(CIPHER_ALGS[index]);
      index++;
    }
  }

  private KMOperationImpl getOperationInstanceFromPool() {
    short index = 0;
    KMOperationImpl impl;
    while (index < operationPool.length) {
      impl = (KMOperationImpl) operationPool[index];
      // Mode is always set. so compare using mode value.
      if (impl.getMode() == KMType.INVALID_VALUE) {
        return impl;
      }
      index++;
    }
    return null;
  }
  
  private KMOperationImpl getHmacSignOperationInstanceFromPool() {
    short index = 0;
    KMOperationImpl impl;
    while (index < hmacSignOperationPool.length) {
      impl = (KMOperationImpl) hmacSignOperationPool[index];
      // Mode is always set. so compare using mode value.
      if (impl.getMode() == KMType.INVALID_VALUE) {
        return impl;
      }
      index++;
    }
    return null;
  }

  private Signature getSignatureInstanceFromPool(byte alg) {
    return (Signature) getInstanceFromPool(sigPool, alg);
  }

  private Cipher getCipherInstanceFromPool(byte alg) {
    return (Cipher) getInstanceFromPool(cipherPool, alg);
  }

  private boolean isResourceBusy(Object obj, byte resourceType) {
    short index = 0;
    while (index < MAX_OPERATION_INSTANCES) {
      if (((KMOperationImpl) operationPool[index]).isResourceMatches(obj, resourceType)
    		  || ((KMOperationImpl) hmacSignOperationPool[index]).isResourceMatches(obj, resourceType)) {
        return true;
      }
      index++;
    }
    return false;
  }

  // This pool implementation can create a maximum of total 4 instances per
  // algorithm. This function returns the unreserved Cipher/Signature instance
  // of type algorithm from pool. If there is no unreserved cipher/signature
  // instance of algorithm type in the pool and Cipher/Signature algorithm
  // instance count is less than 4 then it creates and returns a new
  // Cipher/Signature instance of algorithm type. If there is no unreserved
  // cipher/signature and maximum instance count reaches four it throws
  // exception.
  private Object getInstanceFromPool(Object[] pool, byte alg) {
    short index = 0;
    short instanceCount = 0;
    boolean isCipher = isCipherAlgorithm(alg);
    boolean isSigner = isSignerAlgorithm(alg);
    short maxOperations = MAX_OPERATIONS;
    if (Signature.ALG_HMAC_SHA_256 == alg) {
      maxOperations = HMAC_MAX_OPERATIONS;
    }
    while (index < (short) pool.length) {
      if (instanceCount >= maxOperations) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
        break;
      }
      if (null == pool[index]) {
          // No instance of cipher/signature with this algorithm is found
          if (isCipher) { // Cipher
            pool[index] = getCipherInstance(alg);
          } else if (isSigner) { // Signature
            pool[index] = getSignatureInstance(alg);
          } else {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }
          return pool[index];
      }
      if ((isCipher && (alg == ((Cipher) pool[index]).getAlgorithm()))
          || ((isSigner && (alg == ((Signature) pool[index]).getAlgorithm())))) {
        if (!isResourceBusy(pool[index], RESOURCE_TYPE_CRYPTO)) {
          return pool[index];
        }
        instanceCount++;
      }
      index++;
    }
    return null;
  }
  
  public KMKeyObject getKeyObjectFromPool(byte algo, short secretLength) {	
	KMKeyObject keyObject = null;  
    short maxOperations = MAX_OPERATION_INSTANCES;
    if (KMType.HMAC == algo) {
      maxOperations = HMAC_MAX_OPERATION_INSTANCES;
    }
    if(algo == KMType.AES) {
      if (secretLength == 16) {
        algo = AES_128;
      } else if (secretLength == 32) {
	algo = AES_256;
      } else {
	 CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    }
    short index = 0;
    short usageCount = 0;
    while (index < keysPool.length) {
      if (usageCount >= maxOperations) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
      }
      if (keysPool[index] == null) {
        keyObject = createKeyObjectInstance(algo);
        JCSystem.beginTransaction();
        keysPool[index] = keyObject;
        JCSystem.commitTransaction();
        break;
      }
      keyObject = (KMKeyObject) keysPool[index];
      if (algo == keyObject.getAlgorithm()) {
        // Check if the Object instance is not busy and free to use.
        if (!isResourceBusy(keyObject, RESOURCE_TYPE_KEY)) {
          break;
        }
        usageCount++;
      }
      index++;
    }
    return keyObject;
  }

  public AESKey createAESKey(short keysize) {
    try {
      newRandomNumber(tmpArray, (short) 0, (short) (keysize / 8));
      return createAESKey(tmpArray, (short) 0, (short) (keysize / 8));
    } finally {
      clean();
    }
  }

  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    AESKey key = null;
    short keysize = (short) (length * 8);
    if (keysize == 128) {
      key = (AESKey) aesKeys[KEYSIZE_128_OFFSET];
      key.setKey(buf, (short) startOff);
    } else if (keysize == 256) {
      key = (AESKey) aesKeys[KEYSIZE_256_OFFSET];
      key.setKey(buf, (short) startOff);
    }
    return key;
  }

  public DESKey createTDESKey() {
    try {
      newRandomNumber(tmpArray, (short) 0,
          (short) (KeyBuilder.LENGTH_DES3_3KEY / 8));
      return createTDESKey(tmpArray, (short) 0,
          (short) (KeyBuilder.LENGTH_DES3_3KEY / 8));
    } finally {
      clean();
    }
  }

  public DESKey createTDESKey(byte[] secretBuffer, short secretOff,
      short secretLength) {
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }

  public HMACKey createHMACKey(short keysize) {
    if ((keysize % 8 != 0) || !(keysize >= 64 && keysize <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    try {
      newRandomNumber(tmpArray, (short) 0, (short) (keysize / 8));
      return createHMACKey(tmpArray, (short) 0, (short) (keysize / 8));
    } finally {
      clean();
    }
  }

  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff,
      short secretLength) {
    hmacKey.setKey(secretBuffer, secretOff, secretLength);
    return hmacKey;
  }

  public KeyPair createRsaKeyPair() {
    rsaKeyPair.genKeyPair();
    return rsaKeyPair;
  }

  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff,
      short modLength, byte[] privBuffer, short privOff, short privLength) {
    RSAPrivateKey privKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;
  }

  public KeyPair createECKeyPair() {
    ecKeyPair.genKeyPair();
    return ecKeyPair;
  }

  public ECPrivateKey createEcKey(byte[] privBuffer, short privOff,
      short privLength) {
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    privKey.setS(privBuffer, privOff, privLength);
    return privKey;
  }

  @Override
  public short createSymmetricKey(byte alg, short keysize, byte[] buf,
      short startOff) {
    switch (alg) {
      case KMType.AES:
        AESKey aesKey = createAESKey(keysize);
        return aesKey.getKey(buf, startOff);
      case KMType.DES:
        DESKey desKey = createTDESKey();
        return desKey.getKey(buf, startOff);
      case KMType.HMAC:
        HMACKey hmacKey = createHMACKey(keysize);
        return hmacKey.getKey(buf, startOff);
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return 0;
  }

  @Override
  public void createAsymmetricKey(byte alg, byte[] privKeyBuf,
      short privKeyStart, short privKeyLength, byte[] pubModBuf,
      short pubModStart, short pubModLength, short[] lengths) {
    switch (alg) {
      case KMType.RSA:
        if (RSA_KEY_SIZE != privKeyLength || RSA_KEY_SIZE != pubModLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        KeyPair rsaKey = createRsaKeyPair();
        RSAPrivateKey privKey = (RSAPrivateKey) rsaKey.getPrivate();
        //Copy exponent.
        Util.arrayFillNonAtomic(tmpArray, (short) 0, RSA_KEY_SIZE, (byte) 0);
        lengths[0] = privKey.getExponent(tmpArray, (short) 0);
        if (lengths[0] > privKeyLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayFillNonAtomic(privKeyBuf, privKeyStart, privKeyLength, (byte) 0);
        Util.arrayCopyNonAtomic(tmpArray, (short) 0,
            privKeyBuf, (short) (privKeyStart + privKeyLength - lengths[0]), lengths[0]);
        //Copy modulus
        Util.arrayFillNonAtomic(tmpArray, (short) 0, RSA_KEY_SIZE, (byte) 0);
        lengths[1] = privKey.getModulus(tmpArray, (short) 0);
        if (lengths[1] > pubModLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayFillNonAtomic(pubModBuf, pubModStart, pubModLength, (byte) 0);
        Util.arrayCopyNonAtomic(tmpArray, (short) 0,
            pubModBuf, (short) (pubModStart + pubModLength - lengths[1]), lengths[1]);
        break;
      case KMType.EC:
        KeyPair ecKey = createECKeyPair();
        ECPublicKey ecPubKey = (ECPublicKey) ecKey.getPublic();
        ECPrivateKey ecPrivKey = (ECPrivateKey) ecKey.getPrivate();
        lengths[0] = ecPrivKey.getS(privKeyBuf, privKeyStart);
        lengths[1] = ecPubKey.getW(pubModBuf, pubModStart);
        if (lengths[0] > privKeyLength || lengths[1] > pubModLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
  }

  @Override
  public boolean importSymmetricKey(byte alg, short keysize, byte[] buf,
      short startOff, short length) {
    switch (alg) {
      case KMType.AES:
        createAESKey(buf, startOff, length);
        break;
      case KMType.DES:
        createTDESKey(buf, startOff, length);
        break;
      case KMType.HMAC:
        createHMACKey(buf, startOff, length);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return true;
  }

  @Override
  public boolean importAsymmetricKey(byte alg, byte[] privKeyBuf,
      short privKeyStart, short privKeyLength, byte[] pubModBuf,
      short pubModStart, short pubModLength) {
    switch (alg) {
      case KMType.RSA:
        createRsaKey(pubModBuf, pubModStart, pubModLength, privKeyBuf,
            privKeyStart, privKeyLength);
        break;
      case KMType.EC:
        createEcKey(privKeyBuf, privKeyStart, privKeyLength);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return true;
  }

  @Override
  public void getTrueRandomNumber(byte[] buf, short start, short length) {
    newRandomNumber(buf, start, length);
  }

  @Override
  public void newRandomNumber(byte[] num, short startOff, short length) {
    rng.nextBytes(num, startOff, length);
  }

  @Override
  public void addRngEntropy(byte[] num, short offset, short length) {
    rng.setSeed(num, offset, length);
  }

  public short aesGCMEncrypt(AESKey key,
      byte[] secret, short secretStart, short secretLen, byte[] encSecret,
      short encSecretStart, byte[] nonce, short nonceStart, short nonceLen,
      byte[] authData, short authDataStart, short authDataLen, byte[] authTag,
      short authTagStart, short authTagLen) {
    if (authTagLen != AES_GCM_TAG_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM,
          false);
    }
    aesGcmCipher.init(key, Cipher.MODE_ENCRYPT, nonce, nonceStart, nonceLen);
    aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    short ciphLen = aesGcmCipher.doFinal(secret, secretStart, secretLen,
        encSecret, encSecretStart);
    aesGcmCipher.retrieveTag(authTag, authTagStart, authTagLen);
    return ciphLen;
  }

  @Override
  public short aesGCMEncrypt(byte[] aesKey, short aesKeyStart, short aesKeyLen,
      byte[] secret, short secretStart, short secretLen, byte[] encSecret,
      short encSecretStart, byte[] nonce, short nonceStart, short nonceLen,
      byte[] authData, short authDataStart, short authDataLen, byte[] authTag,
      short authTagStart, short authTagLen) {

    AESKey key = createAESKey(aesKey, aesKeyStart, aesKeyLen);
    return aesGCMEncrypt(
        key,
        secret,
        secretStart,
        secretLen,
        encSecret,
        encSecretStart,
        nonce,
        nonceStart,
        nonceLen,
        authData,
        authDataStart,
        authDataLen,
        authTag,
        authTagStart,
        authTagLen);
  }

  @Override
  public boolean aesGCMDecrypt(byte[] aesKey, short aesKeyStart,
      short aesKeyLen, byte[] encSecret, short encSecretStart,
      short encSecretLen, byte[] secret, short secretStart, byte[] nonce,
      short nonceStart, short nonceLen, byte[] authData, short authDataStart,
      short authDataLen, byte[] authTag, short authTagStart, short authTagLen) {
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM,
          false);
    }
    boolean verification = false;
    AESKey key = createAESKey(aesKey, aesKeyStart, aesKeyLen);
    aesGcmCipher.init(key, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
    aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    // encrypt the secret
    aesGcmCipher.doFinal(encSecret, encSecretStart, encSecretLen, secret,
        secretStart);
    verification = aesGcmCipher.verifyTag(authTag, authTagStart, (short) authTagLen,
        (short) AES_GCM_TAG_LENGTH);
    return verification;
  }

  public HMACKey cmacKdf(KMPreSharedKey preSharedKey, byte[] label, short labelStart,
      short labelLen,
      byte[] context, short contextStart, short contextLength) {
    try {
      // This is hardcoded to requirement - 32 byte output with two concatenated
      // 16 bytes K1 and K2.
      final byte n = 2; // hardcoded
      
      // [i] counter - 32 bits
      short iBufLen = 4;
      short keyOutLen = n * 16;
      //Convert Hmackey to AES Key as the algorithm is ALG_AES_CMAC_128.
      KMHmacKey hmacKey = ((KMHmacKey) preSharedKey);
      hmacKey.getKey(tmpArray, (short) 0);
      aesKeys[KEYSIZE_256_OFFSET].setKey(tmpArray, (short) 0);
      //Initialize the key derivation function.
      kdf.init(aesKeys[KEYSIZE_256_OFFSET], Signature.MODE_SIGN);
      //Clear the tmpArray buffer.
      Util.arrayFillNonAtomic(tmpArray, (short) 0, (short) 256, (byte) 0);

      Util.arrayFillNonAtomic(tmpArray, (short) 0, iBufLen, (byte) 0);
      Util.arrayFillNonAtomic(tmpArray, (short) iBufLen, keyOutLen, (byte) 0);

      byte i = 1;
      short pos = 0;
      while (i <= n) {
        tmpArray[3] = i;
        // 4 bytes of iBuf with counter in it
        kdf.update(tmpArray, (short) 0, (short) iBufLen);
        kdf.update(label, labelStart, (short) labelLen); // label
        kdf.update(CMAC_KDF_CONSTANT_ZERO, (short) 0, (short) CMAC_KDF_CONSTANT_ZERO.length); // 1 byte of 0x00
        kdf.update(context, contextStart, contextLength); // context
        // 4 bytes of L - signature of 16 bytes
        pos = kdf.sign(CMAC_KDF_CONSTANT_L, (short) 0, (short) CMAC_KDF_CONSTANT_L.length, tmpArray,
            (short) (iBufLen + pos));
        i++;
      }
      return createHMACKey(tmpArray, (short) iBufLen, (short) keyOutLen);
    } finally {
      clean();
    }
  }

  public short hmacSign(HMACKey key, byte[] data, short dataStart,
      short dataLength, byte[] mac, short macStart) {
    hmacSignature.init(key, Signature.MODE_SIGN);
    return hmacSignature.sign(data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public boolean hmacVerify(KMComputedHmacKey key, byte[] data, short dataStart,
      short dataLength, byte[] mac, short macStart, short macLength) {
    KMHmacKey hmacKey = (KMHmacKey) key;
    hmacSignature.init(hmacKey.getKey(), Signature.MODE_VERIFY);
    return hmacSignature.verify(data, dataStart, dataLength, mac, macStart,
        macLength);
  }

  @Override
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength,
      byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacSign(key, data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public short hmacKDF(KMMasterKey masterkey, byte[] data, short dataStart,
      short dataLength, byte[] signature, short signatureStart) {
    try {
      AESKey aesKey = ((KMAESKey) masterkey).getKey();
      aesKey.getKey(tmpArray, (short) 0);
      HMACKey key = createHMACKey(tmpArray, (short) 0,
          (short) (aesKey.getSize() / 8));
      return hmacSign(key, data, dataStart, dataLength, signature,
          signatureStart);
    } finally {
      clean();
    }
  }

  @Override
  public short rsaDecipherOAEP256(byte[] secret, short secretStart,
      short secretLength, byte[] modBuffer, short modOff, short modLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
    key.setExponent(secret, (short) secretStart, (short) secretLength);
    key.setModulus(modBuffer, (short) modOff, (short) modLength);
    rsaOaepDecipher.init(key, Cipher.MODE_DECRYPT);
    return rsaOaepDecipher.doFinal(inputDataBuf, (short) inputDataStart, (short) inputDataLength,
        outputDataBuf, (short) outputDataStart);
  }

  public short ecSign256(KMAttestationKey attestationKey,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    Signature.OneShot signer = null;
    try {

      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      signer.init(((KMECPrivateKey) attestationKey).getPrivateKey(), Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
          outputDataBuf, outputDataStart);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }

  private byte mapPurpose(short purpose) {
    switch (purpose) {
      case KMType.ENCRYPT:
        return Cipher.MODE_ENCRYPT;
      case KMType.DECRYPT:
        return Cipher.MODE_DECRYPT;
      case KMType.SIGN:
        return Signature.MODE_SIGN;
      case KMType.VERIFY:
        return Signature.MODE_VERIFY;
    }
    return -1;
  }

  private byte mapSignature256Alg(byte alg, byte padding, byte digest) {
    switch (alg) {
      case KMType.RSA:
        switch (padding) {
          case KMType.RSA_PKCS1_1_5_SIGN: {
            if (digest == KMType.DIGEST_NONE) {
              return KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST;
            } else {
              return Signature.ALG_RSA_SHA_256_PKCS1;
            }
          }
          case KMType.RSA_PSS:
            return Signature.ALG_RSA_SHA_256_PKCS1_PSS;
          case KMType.PADDING_NONE:
            return KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD;
        }
        break;
      case KMType.EC:
        if (digest == KMType.DIGEST_NONE) {
          return KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST;
        } else {
          return Signature.ALG_ECDSA_SHA_256;
        }
      case KMType.HMAC:
        return Signature.ALG_HMAC_SHA_256;
    }
    return -1;
  }

  private byte mapCipherAlg(byte alg, byte padding, byte blockmode, byte digest) {
    switch (alg) {
      case KMType.AES:
        switch (blockmode) {
          case KMType.ECB:
            return Cipher.ALG_AES_BLOCK_128_ECB_NOPAD;
          case KMType.CBC:
            return Cipher.ALG_AES_BLOCK_128_CBC_NOPAD;
          case KMType.CTR:
            return Cipher.ALG_AES_CTR;
          case KMType.GCM:
            return AEADCipher.ALG_AES_GCM;
        }
        break;
      case KMType.DES:
        switch (blockmode) {
          case KMType.ECB:
            return Cipher.ALG_DES_ECB_NOPAD;
          case KMType.CBC:
            return Cipher.ALG_DES_CBC_NOPAD;
        }
        break;
      case KMType.RSA:
        switch (padding) {
          case KMType.PADDING_NONE:
            return Cipher.ALG_RSA_NOPAD;
          case KMType.RSA_PKCS1_1_5_ENCRYPT:
            return Cipher.ALG_RSA_PKCS1;
          case KMType.RSA_OAEP: {
            if (digest == KMType.SHA2_256) {
              return KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1;
            } else {
              KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
            }
          }
        }
        break;
    }
    return -1;
  }

  public Cipher createSymmetricCipher(short alg, short purpose,
      short blockMode, short padding, byte[] secret, short secretStart,
      short secretLength, byte[] ivBuffer, short ivStart, short ivLength, KMKeyObject keyObject) {
    Key key = (Key) keyObject.getKeyObjectInstance();
    Cipher symmCipher = null;
    switch (secretLength) {
      case 16:  
      case 32:  
        ((AESKey) key).setKey(secret, secretStart);
        break;
      case 24:
        ((DESKey) key).setKey(secret, secretStart);
        break;
      default:
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        break;
    }
    short cipherAlg = mapCipherAlg((byte) alg, (byte) padding, (byte) blockMode, (byte) 0);
    symmCipher = getCipherInstanceFromPool((byte) cipherAlg);
    switch (cipherAlg) {
      case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
      case Cipher.ALG_AES_CTR:
        symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, ivLength);
        break;
      case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
      case Cipher.ALG_DES_ECB_NOPAD:
        symmCipher.init(key, mapPurpose(purpose));
        break;
      case Cipher.ALG_DES_CBC_NOPAD:
        // Consume only 8 bytes of iv. the random number for iv is of 16 bytes.
        // While sending back the iv, send only 8 bytes.
        symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, (short) 8);
        break;
      case AEADCipher.ALG_AES_GCM:
        ((AEADCipher) symmCipher).init(key, mapPurpose(purpose), ivBuffer,
            ivStart, ivLength);
        break;
      default:// This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return symmCipher;
  }

  private Signature createHmacSignerVerifier(short purpose, short digest,
    byte[] secret, short secretStart, short secretLength, KMKeyObject keyObject) {
    HMACKey key = (HMACKey) keyObject.getKeyObjectInstance();
    key.setKey(secret, secretStart, secretLength);	  
    return createHmacSignerVerifier(purpose, digest, key);
  }
  
  private Signature createHmacSignerVerifier(short purpose, short digest, HMACKey key) {
    byte alg = Signature.ALG_HMAC_SHA_256;
    if (digest != KMType.SHA2_256) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    Signature hmacSignerVerifier = getSignatureInstanceFromPool(alg);
    hmacSignerVerifier.init(key, (byte) mapPurpose(purpose));
    return hmacSignerVerifier;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg,
      byte digest, byte padding, byte blockMode, byte[] keyBuf, short keyStart,
      short keyLength, byte[] ivBuf, short ivStart, short ivLength,
      short macLength) {
    KMOperationImpl opr = null;
    KMKeyObject keyObject = null;
    switch (alg) {
      case KMType.AES:
      case KMType.DES:
        keyObject = getKeyObjectFromPool(alg, keyLength);	  
        Cipher cipher = createSymmetricCipher(alg, purpose, blockMode, padding,
            keyBuf, keyStart, keyLength, ivBuf, ivStart, ivLength, keyObject);
        opr = getOperationInstanceFromPool();
        // Convert macLength to bytes
        macLength = (short) (macLength / 8);
        opr.setKeyObject(keyObject);
        opr.setCipher(cipher);
        opr.setCipherAlgorithm(alg);
        opr.setBlockMode(blockMode);
        opr.setPaddingAlgorithm(padding);
        opr.setMode(purpose);
        opr.setMacLength(macLength);
        break;
      case KMType.HMAC:
    	keyObject = getKeyObjectFromPool(alg, keyLength);  
        Signature signerVerifier = createHmacSignerVerifier(purpose, digest,
            keyBuf, keyStart, keyLength, keyObject);
        opr = getOperationInstanceFromPool();
        opr.setKeyObject(keyObject);
        opr.setMode(purpose);
        opr.setSignature(signerVerifier);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return opr;
  }

  @Override
  public KMOperation initTrustedConfirmationSymmetricOperation(KMComputedHmacKey computedHmacKey) {
    KMOperationImpl opr = null;
    KMHmacKey key = (KMHmacKey) computedHmacKey;
    short len = key.getKey(tmpArray, (short) 0);
    KMKeyObject keyObject = getKeyObjectFromPool(KMType.HMAC, len); 
    Signature signerVerifier = createHmacSignerVerifier(KMType.VERIFY, KMType.SHA2_256, tmpArray,
    		(short) 0, len, keyObject);
    opr = getHmacSignOperationInstanceFromPool();
    opr.setKeyObject(keyObject);
    opr.setMode(KMType.VERIFY);
    opr.setSignature(signerVerifier);
    return opr;
  }

  public Signature createRsaSigner(short digest, short padding, byte[] secret,
      short secretStart, short secretLength, byte[] modBuffer, short modOff,
      short modLength, KMKeyObject keyObject) {
    byte alg = mapSignature256Alg(KMType.RSA, (byte) padding, (byte) digest);
    byte opMode;
    if (padding == KMType.PADDING_NONE
        || (padding == KMType.RSA_PKCS1_1_5_SIGN && digest == KMType.DIGEST_NONE)) {
      opMode = Cipher.MODE_DECRYPT;
    } else {
      opMode = Signature.MODE_SIGN;
    }
    Signature rsaSigner = getSignatureInstanceFromPool(alg);
    RSAPrivateKey key = (RSAPrivateKey) ((KeyPair)(keyObject.getKeyObjectInstance())).getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaSigner.init(key, opMode);
    return rsaSigner;
  }

  public Cipher createRsaDecipher(short padding, short digest, byte[] secret,
      short secretStart, short secretLength, byte[] modBuffer, short modOff,
      short modLength, KMKeyObject keyObject) {
    byte cipherAlg = mapCipherAlg(KMType.RSA, (byte) padding, (byte) 0, (byte) digest);
    Cipher rsaCipher = getCipherInstanceFromPool(cipherAlg);
    RSAPrivateKey key = (RSAPrivateKey) ((KeyPair)(keyObject.getKeyObjectInstance())).getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key, Cipher.MODE_DECRYPT);
    return rsaCipher;
  }

  public Signature createEcSigner(short digest, byte[] secret,
      short secretStart, short secretLength, KMKeyObject keyObject) {
    byte alg = mapSignature256Alg(KMType.EC, (byte) 0, (byte) digest);
    Signature ecSigner = null;
    ECPrivateKey key = (ECPrivateKey) ((KeyPair)(keyObject.getKeyObjectInstance())).getPrivate();
    key.setS(secret, secretStart, secretLength);
    ecSigner = getSignatureInstanceFromPool(alg);
    ecSigner.init(key, Signature.MODE_SIGN);
    return ecSigner;
  }

  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg,
      byte padding, byte digest, byte[] privKeyBuf, short privKeyStart,
      short privKeyLength, byte[] pubModBuf, short pubModStart,
      short pubModLength) {
    KMOperationImpl opr = null;
    KMKeyObject keyObject = null;
    if (alg == KMType.RSA) {
      switch (purpose) {
        case KMType.SIGN:
          keyObject = getKeyObjectFromPool(alg, privKeyLength); 	
          Signature signer = createRsaSigner(digest, padding, privKeyBuf,
              privKeyStart, privKeyLength, pubModBuf, pubModStart, pubModLength, keyObject);
          opr = getOperationInstanceFromPool();
          opr.setKeyObject(keyObject);
          opr.setSignature(signer);
          opr.setCipherAlgorithm(alg);
          opr.setPaddingAlgorithm(padding);
          opr.setMode(purpose);
          break;
        case KMType.DECRYPT:
          keyObject = getKeyObjectFromPool(alg, privKeyLength);
          Cipher decipher = createRsaDecipher(padding, digest, privKeyBuf,
              privKeyStart, privKeyLength, pubModBuf, pubModStart, pubModLength, keyObject);
          opr = getOperationInstanceFromPool();
          opr.setKeyObject(keyObject);
          opr.setCipher(decipher);
          opr.setCipherAlgorithm(alg);
          opr.setPaddingAlgorithm(padding);
          opr.setMode(purpose);
          break;
        default:
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          break;
      }
    } else if (alg == KMType.EC) {
      switch (purpose) {
        case KMType.SIGN:
          keyObject = getKeyObjectFromPool(alg, privKeyLength);	
          Signature signer = createEcSigner(digest, privKeyBuf, privKeyStart,
              privKeyLength, keyObject);
          opr = getOperationInstanceFromPool();
          opr.setKeyObject(keyObject);
          opr.setMode(purpose);
          opr.setSignature(signer);
          break;
        default:
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          break;
      }
    } else {
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    return opr;

  }

  @Override
  public KMAttestationCert getAttestationCert(boolean rsaCert) {
    return KMAttestationCertImpl.instance(rsaCert);
  }

  @Override
  public KMPKCS8Decoder getPKCS8DecoderInstance() {
    return KMPKCS8DecoderImpl.instance();
  }

  @Override
  public short cmacKDF(KMPreSharedKey pSharedKey, byte[] label,
      short labelStart, short labelLen, byte[] context, short contextStart,
      short contextLength, byte[] keyBuf, short keyStart) {
    HMACKey key = cmacKdf(pSharedKey, label, labelStart, labelLen, context,
        contextStart, contextLength);
    return key.getKey(keyBuf, keyStart);
  }
  
  private short getProvisionDataBufferOffset(byte dataType) {
    switch(dataType) {
    case CERTIFICATE_CHAIN:
      return CERT_CHAIN_OFFSET;
    case CERTIFICATE_ISSUER:
      return CERT_ISSUER_OFFSET;
    case CERTIFICATE_EXPIRY:
      return CERT_EXPIRY_OFFSET;
    default:
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    return 0;
  }

  private void persistProvisionData(byte[] buf, short off, short len, short maxSize, short copyToOff) {
    if (len > maxSize) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    Util.arrayCopy(buf, off, provisionData, Util.setShort(provisionData, copyToOff, len), len);
  }

  private void persistCertificateChain(byte[] certChain, short certChainOff, short certChainLen) {
    persistProvisionData(certChain, certChainOff, certChainLen,
        KMConfigurations.CERT_CHAIN_MAX_SIZE, CERT_CHAIN_OFFSET);
  }
  
  private void persistCertficateIssuer(byte[] certIssuer, short certIssuerOff, short certIssuerLen) {
    persistProvisionData(certIssuer, certIssuerOff, certIssuerLen,
        KMConfigurations.CERT_ISSUER_MAX_SIZE, CERT_ISSUER_OFFSET);
  }
  
  private void persistCertificateExpiryTime(byte[] certExpiry, short certExpiryOff, short certExpiryLen) {
    persistProvisionData(certExpiry, certExpiryOff, certExpiryLen,
        KMConfigurations.CERT_EXPIRY_MAX_SIZE, CERT_EXPIRY_OFFSET);
  }

  @Override
  public void persistProvisionData(byte[] buffer, short certChainOff, short certChainLen,
      short certIssuerOff, short certIssuerLen, short certExpiryOff ,short certExpiryLen) {
    // All the buffers uses first two bytes for length. The certificate chain
    // is stored as shown below.
    //  _____________________________________________________
    // | 2 Bytes | 1 Byte | 3 Bytes | Cert1 |  Cert2 |...
    // |_________|________|_________|_______|________|_______
    // First two bytes holds the length of the total buffer.
    // CBOR format:
    // Next single byte holds the byte string header.
    // Next 3 bytes holds the total length of the certificate chain.
    // clear buffer.
    Util.arrayFill(provisionData, (short) 0, (short) provisionData.length, (byte) 0);
    // Persist data.
    persistCertificateChain(buffer, certChainOff, certChainLen);
    persistCertficateIssuer(buffer, certIssuerOff, certIssuerLen);
    persistCertificateExpiryTime(buffer, certExpiryOff, certExpiryLen);
  }

  @Override
  public short readProvisionedData(byte dataType, byte[] buf, short offset) {
    short provisionBufOffset = getProvisionDataBufferOffset(dataType);
    short len = Util.getShort(provisionData, provisionBufOffset);
    Util.arrayCopyNonAtomic(provisionData, (short) (2 + provisionBufOffset), buf, offset, len);
    return len;
  }

  @Override
  public short getProvisionedDataLength(byte dataType) {
    short provisionBufOffset = getProvisionDataBufferOffset(dataType);
    return Util.getShort(provisionData, provisionBufOffset);
  }

  @Override
  public boolean isBootSignalEventSupported() {
    return false;
  }

  @Override
  public boolean isDeviceRebooted() {
    return false;
  }

  @Override
  public void clearDeviceBooted(boolean resetBootFlag) {
    // To be filled
  }

  @Override
  public void onSave(Element element) {
    element.write(provisionData);
    KMAESKey.onSave(element, masterKey);
    KMECPrivateKey.onSave(element, attestationKey);
    KMHmacKey.onSave(element, preSharedKey);
    KMHmacKey.onSave(element, computedHmacKey);
    element.write(oemRootPublicKey);
  }

  @Override
  public void onRestore(Element element, short oldVersion, short currentVersion) {
    provisionData = (byte[]) element.readObject();
    masterKey = KMAESKey.onRestore(element);
    attestationKey = KMECPrivateKey.onRestore(element);
    preSharedKey = KMHmacKey.onRestore(element);
    computedHmacKey = KMHmacKey.onRestore(element);
    if (oldVersion == 0x200) {
      createOemRootPublicKey();
    } else {
      oemRootPublicKey = (byte[]) element.readObject();
    }
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    short count =
        (short) (KMAESKey.getBackupPrimitiveByteCount() +
            KMECPrivateKey.getBackupPrimitiveByteCount() +
            KMHmacKey.getBackupPrimitiveByteCount() +
            KMHmacKey.getBackupPrimitiveByteCount());
    return count;
  }

  @Override
  public short getBackupObjectCount() {
    short count =
        (short) (2 + /* provisionData buffer + oemRootPublicKey */
            KMAESKey.getBackupObjectCount() +
            KMECPrivateKey.getBackupObjectCount() +
            KMHmacKey.getBackupObjectCount() +
            KMHmacKey.getBackupObjectCount());
    return count;
  }

  @Override
  public boolean isUpgrading() {
    return UpgradeManager.isUpgrading();
  }

  @Override
  public KMMasterKey createMasterKey(short keySizeBits) {
    try {
      if (masterKey == null) {
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
            keySizeBits, false);
        masterKey = new KMAESKey(key);
        short keyLen = (short) (keySizeBits / 8);
        getTrueRandomNumber(tmpArray, (short) 0, keyLen);
        masterKey.setKey(tmpArray, (short) 0);
      }
      return (KMMasterKey) masterKey;
    } finally {
      clean();
    }
  }

  @Override
  public KMAttestationKey createAttestationKey(byte[] keyData, short offset,
      short length) {
    if (attestationKey == null) {
      // Strongbox supports only P-256 curve for EC key.
      KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      initECKey(ecKeyPair);
      attestationKey = new KMECPrivateKey(ecKeyPair);
    }
    attestationKey.setS(keyData, offset, length);
    return (KMAttestationKey) attestationKey;
  }
  
  @Override
  public KMComputedHmacKey createComputedHmacKey(byte[] keyData, short offset, short length) {
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (computedHmacKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (length * 8),
          false);
      computedHmacKey = new KMHmacKey(key);
    }
    computedHmacKey.setKey(keyData, offset, length);
    return (KMComputedHmacKey) computedHmacKey;
  }  

  @Override
  public KMPreSharedKey createPresharedKey(byte[] keyData, short offset, short length) {
    short lengthInBits = (short) (length * 8);
    if ((lengthInBits % 8 != 0) || !(lengthInBits >= 64 && lengthInBits <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (preSharedKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, lengthInBits,
          false);
      preSharedKey = new KMHmacKey(key);
    }
    preSharedKey.setKey(keyData, offset, length);
    return (KMPreSharedKey) preSharedKey;
  }

  @Override
  public KMMasterKey getMasterKey() {
    return (KMMasterKey) masterKey;
  }

  @Override
  public KMAttestationKey getAttestationKey() {
    return (KMAttestationKey) attestationKey;
  }

  @Override
  public KMPreSharedKey getPresharedKey() {
    return (KMPreSharedKey) preSharedKey;
  }

  @Override
  public void releaseAllOperations() {
    short index = 0;
    while (index < operationPool.length) {
      ((KMOperationImpl) operationPool[index]).abort();
      ((KMOperationImpl) hmacSignOperationPool[index]).abort();
      index++;
    }
  }

  @Override
  public KMComputedHmacKey getComputedHmacKey() {
    return computedHmacKey;
  }
  
  private void createOemRootPublicKey() {
    // Please note that this is a dummy EC P256 Public Key. Replace below key with a real OEM Root
    // EC P256 public key while upgrading the Applet from data version 2.0 to 3.0. This change
    // is not required if the Applet is installed first time with version 3.0.
    oemRootPublicKey = new byte[]{
        (byte) 0x04, (byte) 0xa7, (byte) 0xf7, (byte) 0x4e, (byte) 0xf2, (byte) 0x21, (byte) 0xdd,
        (byte) 0x1f, (byte) 0xdb, (byte) 0x19, (byte) 0x87, (byte) 0xbf, (byte) 0x38, (byte) 0x05,
        (byte) 0xed, (byte) 0x4e, (byte) 0x82, (byte) 0x84, (byte) 0xaf, (byte) 0x92, (byte) 0x99,
        (byte) 0x36, (byte) 0x7e, (byte) 0xb8, (byte) 0xba, (byte) 0xda, (byte) 0x59, (byte) 0xfe,
        (byte) 0xd6, (byte) 0x38, (byte) 0x70, (byte) 0x60, (byte) 0xda, (byte) 0xd5, (byte) 0x05,
        (byte) 0xf2, (byte) 0x83, (byte) 0xf6, (byte) 0x0b, (byte) 0xd2, (byte) 0x82, (byte) 0xcb,
        (byte) 0x8e, (byte) 0x21, (byte) 0xf5, (byte) 0xf7, (byte) 0x52, (byte) 0xff, (byte) 0x82,
        (byte) 0x55, (byte) 0xca, (byte) 0xf2, (byte) 0x57, (byte) 0x07, (byte) 0x8e, (byte) 0xea,
        (byte) 0x7a, (byte) 0xb0, (byte) 0x82, (byte) 0x59, (byte) 0x84, (byte) 0xe7, (byte) 0x75,
        (byte) 0xfb, (byte) 0xb2};
  }

  @Override
  public short messageDigest256(byte[] inBuff, short inOffset,
      short inLength, byte[] outBuff, short outOffset) {
    MessageDigest.OneShot mDigest = null;
    short len = 0;
    try {
      mDigest = MessageDigest.OneShot.open(MessageDigest.ALG_SHA_256);
      len = mDigest.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    } finally {
      if (mDigest != null) {
        mDigest.close();
        mDigest = null;
      }
    }
    return len;
  }

  private KMKeyObject createKeyObjectInstance(byte alg) {
    Object keyObject = null;
    switch (alg) {
    case AES_128:
      keyObject = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET,
          KeyBuilder.LENGTH_AES_128, false);
      break;
    case AES_256:
      keyObject = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET,
          KeyBuilder.LENGTH_AES_256, false);
      break;
    case KMType.DES:
      keyObject = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES_TRANSIENT_RESET,
          KeyBuilder.LENGTH_DES3_3KEY, false);
      break;
    case KMType.RSA:
      keyObject = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
      break;
    case KMType.EC:
      keyObject = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      initECKey((KeyPair) keyObject);
      break;
    case KMType.HMAC:
      keyObject = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC_TRANSIENT_RESET,
          (short) 512, false);
      break;
    default:
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    KMKeyObject ptr = new KMKeyObject();
    ptr.setKeyObjectData(alg, keyObject);
    return ptr;
  }

  @Override
  public void persistOEMRootPublicKey(byte[] inBuff, short inOffset, short inLength) {
    if (inLength != 65) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    Util.arrayCopy(inBuff, inOffset, oemRootPublicKey, (short) 0, inLength);
  }

  @Override
  public short readOEMRootPublicKey(byte[] buf, short off) {
    Util.arrayCopyNonAtomic(oemRootPublicKey, (short) 0, buf, off, (short) oemRootPublicKey.length);
    return (short) oemRootPublicKey.length;
  }

  @Override
  public boolean ecVerify256(byte[] keyBuf, short keyBufStart, short keyBufLen, 
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signature, short signatureOff, short signatureLen) {
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    ecPublicKey.setW(keyBuf, keyBufStart, keyBufLen);
    Signature.OneShot signer = null;
    try {

      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      signer.init(ecPublicKey, Signature.MODE_VERIFY);
      return signer.verify(inputDataBuf, inputDataStart, inputDataLength,
          signature, signatureOff, signatureLen);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }

    
}
