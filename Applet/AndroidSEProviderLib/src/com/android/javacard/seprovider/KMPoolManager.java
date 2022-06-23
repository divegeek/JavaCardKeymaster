/*
 * Copyright(C) 2021 The Android Open Source Project
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
import javacard.framework.JCSystem;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.HMACKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * This class manages all the pool instances.
 */
public class KMPoolManager {

  public static final short MAX_OPERATION_INSTANCES = 4;
  private static final short HMAC_MAX_OPERATION_INSTANCES = 8;
  public static final byte AES_128 = 0x04;
  public static final byte AES_256 = 0x05;
  //Resource type constants
  public static final byte RESOURCE_TYPE_CRYPTO = 0x00;
  public static final byte RESOURCE_TYPE_KEY = 0x01;
  // static final variables
  // --------------------------------------------------------------
  // P-256 Curve Parameters
  static byte[] secp256r1_P;
  static byte[] secp256r1_A;

  static byte[] secp256r1_B;
  static byte[] secp256r1_S;

  // Uncompressed form
  static byte[] secp256r1_UCG;
  static byte[] secp256r1_N;
  static final short secp256r1_H = 1;
  // --------------------------------------------------------------  
  
  // Cipher pool
  private Object[] cipherPool;
  // Signature pool
  private Object[] signerPool;
  // Keyagreement pool
  private Object[] keyAgreementPool;
  // KMOperationImpl pool
  private Object[] operationPool;
  // Hmac signer pool which is used to support TRUSTED_CONFIRMATION_REQUIRED tag.
  private Object[] hmacSignOperationPool;
  
  private Object[] keysPool;
  // RKP uses AESGCM and HMAC in generateCSR flow.
  KMOperation rkpOPeration;
  Cipher rkpAesGcm;
  Signature rkpHmac;
  KMKeyObject rkpHmacKey;
  KMKeyObject rkpAesKey;

  final byte[] KEY_ALGS = {
      AES_128,
      AES_256,
	    KMType.DES,
	    KMType.RSA,
	    KMType.EC,
	    KMType.HMAC,
  };
  
  final byte[] CIPHER_ALGS = {
      Cipher.ALG_AES_BLOCK_128_CBC_NOPAD,
      Cipher.ALG_AES_BLOCK_128_ECB_NOPAD,
      Cipher.ALG_DES_CBC_NOPAD,
      Cipher.ALG_DES_ECB_NOPAD,
      Cipher.ALG_AES_CTR,
      Cipher.ALG_RSA_PKCS1,
      KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1,
      KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256,
      Cipher.ALG_RSA_NOPAD,
      AEADCipher.ALG_AES_GCM};

  final byte[] SIG_ALGS = {
      Signature.ALG_RSA_SHA_256_PKCS1,
      Signature.ALG_RSA_SHA_256_PKCS1_PSS,
      Signature.ALG_ECDSA_SHA_256,
      Signature.ALG_HMAC_SHA_256,
      KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD,
      KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST,
      KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST};

  final byte[] KEY_AGREE_ALGS = {KeyAgreement.ALG_EC_SVDP_DH_PLAIN};


  private static KMPoolManager poolManager;

  public static KMPoolManager getInstance() {
    if (poolManager == null) {
      poolManager = new KMPoolManager();
    }
    return poolManager;
  }

  public static void initStatics() {
	    secp256r1_P = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
	        (byte) 0x00,
	        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
	        (byte) 0x00,
	        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
	        (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	        (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF};

	    secp256r1_A = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
	        (byte) 0x00,
	        (byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
	        (byte) 0x00,
	        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0xFF,
	        (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	        (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFC};

	    secp256r1_B = new byte[]{(byte) 0x5A, (byte) 0xC6, (byte) 0x35, (byte) 0xD8, (byte) 0xAA,
	        (byte) 0x3A,
	        (byte) 0x93, (byte) 0xE7, (byte) 0xB3, (byte) 0xEB, (byte) 0xBD, (byte) 0x55, (byte) 0x76,
	        (byte) 0x98,
	        (byte) 0x86, (byte) 0xBC, (byte) 0x65, (byte) 0x1D, (byte) 0x06, (byte) 0xB0, (byte) 0xCC,
	        (byte) 0x53,
	        (byte) 0xB0, (byte) 0xF6, (byte) 0x3B, (byte) 0xCE, (byte) 0x3C, (byte) 0x3E, (byte) 0x27,
	        (byte) 0xD2,
	        (byte) 0x60, (byte) 0x4B};

	    secp256r1_S = new byte[]{(byte) 0xC4, (byte) 0x9D, (byte) 0x36, (byte) 0x08, (byte) 0x86,
	        (byte) 0xE7,
	        (byte) 0x04, (byte) 0x93, (byte) 0x6A, (byte) 0x66, (byte) 0x78, (byte) 0xE1, (byte) 0x13,
	        (byte) 0x9D,
	        (byte) 0x26, (byte) 0xB7, (byte) 0x81, (byte) 0x9F, (byte) 0x7E, (byte) 0x90};

	    // Uncompressed form
	    secp256r1_UCG = new byte[]{(byte) 0x04, (byte) 0x6B, (byte) 0x17, (byte) 0xD1, (byte) 0xF2,
	        (byte) 0xE1,
	        (byte) 0x2C, (byte) 0x42, (byte) 0x47, (byte) 0xF8, (byte) 0xBC, (byte) 0xE6, (byte) 0xE5,
	        (byte) 0x63,
	        (byte) 0xA4, (byte) 0x40, (byte) 0xF2, (byte) 0x77, (byte) 0x03, (byte) 0x7D, (byte) 0x81,
	        (byte) 0x2D,
	        (byte) 0xEB, (byte) 0x33, (byte) 0xA0, (byte) 0xF4, (byte) 0xA1, (byte) 0x39, (byte) 0x45,
	        (byte) 0xD8,
	        (byte) 0x98, (byte) 0xC2, (byte) 0x96, (byte) 0x4F, (byte) 0xE3, (byte) 0x42, (byte) 0xE2,
	        (byte) 0xFE,
	        (byte) 0x1A, (byte) 0x7F, (byte) 0x9B, (byte) 0x8E, (byte) 0xE7, (byte) 0xEB, (byte) 0x4A,
	        (byte) 0x7C,
	        (byte) 0x0F, (byte) 0x9E, (byte) 0x16, (byte) 0x2B, (byte) 0xCE, (byte) 0x33, (byte) 0x57,
	        (byte) 0x6B,
	        (byte) 0x31, (byte) 0x5E, (byte) 0xCE, (byte) 0xCB, (byte) 0xB6, (byte) 0x40, (byte) 0x68,
	        (byte) 0x37,
	        (byte) 0xBF, (byte) 0x51, (byte) 0xF5};

	    secp256r1_N = new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00,
	        (byte) 0x00,
	        (byte) 0x00, (byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
	        (byte) 0xFF,
	        (byte) 0xFF, (byte) 0xFF, (byte) 0xBC, (byte) 0xE6, (byte) 0xFA, (byte) 0xAD, (byte) 0xA7,
	        (byte) 0x17,
	        (byte) 0x9E, (byte) 0x84, (byte) 0xF3, (byte) 0xB9, (byte) 0xCA, (byte) 0xC2, (byte) 0xFC,
	        (byte) 0x63,
	        (byte) 0x25, (byte) 0x51};
	  }
  
  private KMPoolManager() {
    initStatics();  
    cipherPool = new Object[(short) (CIPHER_ALGS.length * MAX_OPERATION_INSTANCES)];
    // Extra 4 algorithms are used to support TRUSTED_CONFIRMATION_REQUIRED feature.
    signerPool = new Object[(short) ((SIG_ALGS.length * MAX_OPERATION_INSTANCES) + MAX_OPERATION_INSTANCES)];
    keyAgreementPool = new Object[(short) (KEY_AGREE_ALGS.length * MAX_OPERATION_INSTANCES)];
    
    keysPool = new Object[(short) ((KEY_ALGS.length * MAX_OPERATION_INSTANCES) + MAX_OPERATION_INSTANCES)];
    operationPool = new Object[MAX_OPERATION_INSTANCES];
    hmacSignOperationPool = new Object[MAX_OPERATION_INSTANCES];
    /* Initialize pools */
    initializeOperationPool();
    initializeHmacSignOperationPool();
    initializeSignerPool();
    initializeCipherPool();
    initializeKeyAgreementPool();
    initializeKeysPool();
    // Initialize the Crypto and Key objects required for RKP flow.
    initializeRKpObjects();
  }

  private void initializeRKpObjects() {
    rkpOPeration = new KMOperationImpl();
    rkpAesGcm = Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    rkpHmac = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
    rkpAesKey = createKeyObjectInstance(AES_256);
    rkpHmacKey = createKeyObjectInstance(KMType.HMAC);
  }

  private void initializeKeysPool() {
    for(short index = 0; index < KEY_ALGS.length; index++) {
      keysPool[index] = createKeyObjectInstance(KEY_ALGS[index]);
    }
  }
  
  private void initializeOperationPool() {
    for(short index = 0; index < MAX_OPERATION_INSTANCES; index++) {
      operationPool[index] = new KMOperationImpl();
    }
  }

  private void initializeHmacSignOperationPool() {
    for(short index = 0; index < MAX_OPERATION_INSTANCES; index++) {
      hmacSignOperationPool[index] = new KMOperationImpl();
    }
  }
  
  // Create a signature instance of each algorithm once.
  private void initializeSignerPool() { 
    short index;
    for(index = 0; index < SIG_ALGS.length; index++) {
      signerPool[index] = getSignatureInstance(SIG_ALGS[index]);
    }

    // Allocate extra 4 HMAC signer instances required for trusted confirmation
    for(short len = (short) (index + 4); index < len; index++) {
      signerPool[index] = getSignatureInstance(Signature.ALG_HMAC_SHA_256);
    }
  }

  //Create a cipher instance of each algorithm once.
  private void initializeCipherPool() {
    for(short index = 0; index < CIPHER_ALGS.length; index++) {
      cipherPool[index] = getCipherInstance(CIPHER_ALGS[index]);
    }
  }

  private void initializeKeyAgreementPool() {
    for(short index = 0; index < KEY_AGREE_ALGS.length; index++) {
      keyAgreementPool[index] = getKeyAgreementInstance(KEY_AGREE_ALGS[index]);
    }
  }

  private Object[] getCryptoPoolInstance(short purpose) {
    switch (purpose) {
      case KMType.AGREE_KEY:
        return keyAgreementPool;

      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        return cipherPool;

      case KMType.SIGN:
      case KMType.VERIFY:
        return signerPool;

      default:
        KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    return null;
  }

  private Object createInstance(short purpose, short alg) {
    switch (purpose) {
      case KMType.AGREE_KEY:
        return getKeyAgreementInstance((byte) alg);

      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        return getCipherInstance((byte) alg);

      case KMType.SIGN:
      case KMType.VERIFY:
        return getSignatureInstance((byte) alg);

      default:
        KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    return null;
  }

  private KeyAgreement getKeyAgreementInstance(byte alg) {
    return KeyAgreement.getInstance(alg, false);
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

  private Cipher getCipherInstance(byte alg) {
    if ((KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1 == alg) ||
        (KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256 == alg)) {
      return new KMRsaOAEPEncoding(alg);
    } else {
      return Cipher.getInstance(alg, false);
    }
  }

  /**
   * Returns the first available resource from operation pool.
   *
   * @return instance of the available resource or null if no resource is available.
   */
  public KMOperation getResourceFromOperationPool(boolean isTrustedConfOpr) {
    short index = 0;
    KMOperationImpl impl;
    Object[] oprPool;
    if(isTrustedConfOpr) {
    	oprPool = hmacSignOperationPool;
    } else {
    	oprPool = operationPool;
    }
    while (index < oprPool.length) {
      impl = (KMOperationImpl) oprPool[index];
      // Mode is always set. so compare using mode value.
      if (impl.getPurpose() == KMType.INVALID_VALUE) {
        return impl;
      }
      index++;
    }
    return null;
  }

  private byte getAlgorithm(short purpose, Object object) {
    switch (purpose) {
      case KMType.AGREE_KEY:
        return ((KeyAgreement) object).getAlgorithm();

      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        return ((Cipher) object).getAlgorithm();

      case KMType.SIGN:
      case KMType.VERIFY:
        return ((Signature) object).getAlgorithm();

      default:
        KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    return 0;
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

  private void setObject(short purpose, KMOperation operation, Object obj) {
    switch (purpose) {
      case KMType.AGREE_KEY:
        ((KMOperationImpl) operation).setKeyAgreement((KeyAgreement) obj);
        break;
      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        ((KMOperationImpl) operation).setCipher((Cipher) obj);
        break;
      case KMType.SIGN:
      case KMType.VERIFY:
        ((KMOperationImpl) operation).setSignature((Signature) obj);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
  }

  private void reserveOperation(KMOperation operation, short purpose, short strongboxAlgType,
      short padding, short blockMode, short macLength, Object obj, KMKeyObject keyObject) {
    ((KMOperationImpl) operation).setPurpose(purpose);
    ((KMOperationImpl) operation).setAlgorithmType(strongboxAlgType);
    ((KMOperationImpl) operation).setPaddingAlgorithm(padding);
    ((KMOperationImpl) operation).setBlockMode(blockMode);
    ((KMOperationImpl) operation).setMacLength(macLength);
    ((KMOperationImpl) operation).setKeyObject(keyObject);
    setObject(purpose, operation, obj);
  }
  
  public KMOperation getRKpOperation(short purpose, short alg, short strongboxAlgType,
      short padding, short blockMode, short macLength) {
    if (((KMOperationImpl) rkpOPeration).getPurpose() != KMType.INVALID_VALUE) {
      // Should not come here.
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    Object cryptoObj = null;
    KMKeyObject keyObject = null;

    switch (alg) {
    case AEADCipher.ALG_AES_GCM:
      cryptoObj = rkpAesGcm;
      keyObject = rkpAesKey;
      break;
    case Signature.ALG_HMAC_SHA_256:
      cryptoObj = rkpHmac;
      keyObject = rkpHmacKey;
      break;
    default:
      // Should not come here.
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
      break;
    }
    reserveOperation(rkpOPeration, purpose, strongboxAlgType, padding, blockMode, macLength,
        cryptoObj, keyObject);
    return rkpOPeration;
  }


  public KMOperation getOperationImpl(short purpose, short alg, short strongboxAlgType,
      short padding,
      short blockMode, short macLength, short secretLength, boolean isTrustedConfOpr) {
    KMOperation operation;
    // Throw exception if no resource from operation pool is available.
    if (null == (operation = getResourceFromOperationPool(isTrustedConfOpr))) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    // Get one of the pool instances (cipher / signer / keyAgreement) based on purpose.
    Object[] pool = getCryptoPoolInstance(purpose);
    short index = 0;
    short usageCount = 0;
    short maxOperations = MAX_OPERATION_INSTANCES;
    if (Signature.ALG_HMAC_SHA_256 == alg) {
      maxOperations = HMAC_MAX_OPERATION_INSTANCES;
    }

    KMKeyObject keyObject = getKeyObjectFromPool(alg, secretLength, maxOperations);    
    while (index < pool.length) {
      if (usageCount >= maxOperations) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
      }
      if (pool[index] == null) {
        // Create one of the instance (Cipher / Signer / KeyAgreement] based on purpose.
        Object cipherObject = createInstance(purpose, alg);
        JCSystem.beginTransaction();
        pool[index] = cipherObject;
        JCSystem.commitTransaction();
        reserveOperation(operation, purpose, strongboxAlgType, padding, blockMode, macLength,
            pool[index], keyObject);
        break;
      }
      if (alg == getAlgorithm(purpose, pool[index])) {
        // Check if the crypto instance is not busy and free to use.
        if (!isResourceBusy(pool[index], RESOURCE_TYPE_CRYPTO)) {
          reserveOperation(operation, purpose, strongboxAlgType, padding, blockMode, macLength,
              pool[index], keyObject);
          break;
        }
        usageCount++;
      }
      index++;
    }
    return operation;
  }

  public KMKeyObject getKeyObjectFromPool(short alg, short secretLength, short maxOperations) {	
	KMKeyObject keyObject = null;  
	byte algo = mapAlgorithm(alg, secretLength);
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
  
  private byte mapAlgorithm(short alg, short secretLength) {
    byte algo = 0;
    switch (alg) {
    case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
    case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
    case Cipher.ALG_AES_CTR:
    case AEADCipher.ALG_AES_GCM:
      if (secretLength == 16) {
        algo = AES_128;
      } else if (secretLength == 32) {
        algo = AES_256;
      } else {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
      break;
    case Cipher.ALG_DES_CBC_NOPAD:
    case Cipher.ALG_DES_ECB_NOPAD:
      algo = KMType.DES;
      break;
    case Cipher.ALG_RSA_PKCS1:
    case KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1:
    case KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256:
    case Cipher.ALG_RSA_NOPAD:
    case Signature.ALG_RSA_SHA_256_PKCS1:
    case Signature.ALG_RSA_SHA_256_PKCS1_PSS:
    case KMRsa2048NoDigestSignature.ALG_RSA_SIGN_NOPAD:
    case KMRsa2048NoDigestSignature.ALG_RSA_PKCS1_NODIGEST:
      algo = KMType.RSA;
      break;
    case Signature.ALG_ECDSA_SHA_256:
    case KMEcdsa256NoDigestSignature.ALG_ECDSA_NODIGEST:
    case KeyAgreement.ALG_EC_SVDP_DH_PLAIN:
      algo = KMType.EC;
      break;
    case Signature.ALG_HMAC_SHA_256:
      algo = KMType.HMAC;
      break;
    default:
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    return algo;
  }
  
  public void initECKey(KeyPair ecKeyPair) {
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
  
  public void powerReset() {
    short index = 0;
    while (index < operationPool.length) {
      ((KMOperationImpl) operationPool[index]).abort();
      ((KMOperationImpl) hmacSignOperationPool[index]).abort();
      index++;
    }
    // release rkp operation
    rkpOPeration.abort();
  }

}
