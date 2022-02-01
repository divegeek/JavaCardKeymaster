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

import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMOperation;

import javacard.framework.JCSystem;
import javacard.security.KeyAgreement;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * This class manages all the pool instances.
 */
public class KMPoolManager {

  public static final short MAX_OPERATION_INSTANCES = 4;
  private static final short HMAC_MAX_OPERATION_INSTANCES = 8;
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

  private KMPoolManager() {
    cipherPool = new Object[(short) (CIPHER_ALGS.length * 4)];
    // Extra 4 algorithms are used to support TRUSTED_CONFIRMATION_REQUIRED feature.
    signerPool = new Object[(short) ((SIG_ALGS.length * 4) + 4)];
    keyAgreementPool = new Object[(short) (KEY_AGREE_ALGS.length * 4)];
    operationPool = new Object[4];
    hmacSignOperationPool = new Object[4];
    /* Initialize pools */
    initializeOperationPool();
    initializeHmacSignOperationPool();
    initializeSignerPool();
    initializeCipherPool();
    initializeKeyAgreementPool();
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
  private void initializeSignerPool() {
    short index = 0;
    while (index < SIG_ALGS.length) {
      signerPool[index] = getSignatureInstance(SIG_ALGS[index]);
      index++;
    }
  }

  //Create a cipher instance of each algorithm once.
  private void initializeCipherPool() {
    short index = 0;
    while (index < CIPHER_ALGS.length) {
      cipherPool[index] = getCipherInstance(CIPHER_ALGS[index]);
      index++;
    }
  }

  private void initializeKeyAgreementPool() {
    short index = 0;
    while (index < KEY_AGREE_ALGS.length) {
      keyAgreementPool[index] = getKeyAgreementInstance(KEY_AGREE_ALGS[index]);
      index++;
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
    if (isTrustedConfOpr) {
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

  private boolean isResourceBusy(Object obj) {
    short index = 0;
    while (index < MAX_OPERATION_INSTANCES) {
      if (((KMOperationImpl) operationPool[index]).isResourceMatches(obj)
          || ((KMOperationImpl) hmacSignOperationPool[index]).isResourceMatches(obj)) {
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
      short padding, short blockMode, short macLength, Object obj) {
    ((KMOperationImpl) operation).setPurpose(purpose);
    ((KMOperationImpl) operation).setAlgorithmType(strongboxAlgType);
    ((KMOperationImpl) operation).setPaddingAlgorithm(padding);
    ((KMOperationImpl) operation).setBlockMode(blockMode);
    ((KMOperationImpl) operation).setMacLength(macLength);
    setObject(purpose, operation, obj);
  }


  public KMOperation getOperationImpl(short purpose, short alg, short strongboxAlgType,
      short padding,
      short blockMode, short macLength, boolean isTrustedConfOpr) {
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

    while (index < pool.length) {
      if (usageCount >= maxOperations) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
      }
      if (pool[index] == null) {
        // Create one of the instance (Cipher / Signer / KeyAgreement] based on purpose.
        JCSystem.beginTransaction();
        pool[index] = createInstance(purpose, alg);
        JCSystem.commitTransaction();
        reserveOperation(operation, purpose, strongboxAlgType, padding, blockMode, macLength,
            pool[index]);
        break;
      }
      if (alg == getAlgorithm(purpose, pool[index])) {
        // Check if the crypto instance is not busy and free to use.
        if (!isResourceBusy(pool[index])) {
          reserveOperation(operation, purpose, strongboxAlgType, padding, blockMode, macLength,
              pool[index]);
          break;
        }
        usageCount++;
      }
      index++;
    }
    return operation;
  }

  public void powerReset() {
    short index = 0;
    while (index < operationPool.length) {
      ((KMOperationImpl) operationPool[index]).abort();
      ((KMOperationImpl) hmacSignOperationPool[index]).abort();
      index++;
    }
  }

}
