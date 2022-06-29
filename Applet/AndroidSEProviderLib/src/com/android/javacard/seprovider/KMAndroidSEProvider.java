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
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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
import javacard.security.KeyAgreement;

public class KMAndroidSEProvider implements KMSEProvider {

  public static final short AES_GCM_TAG_LENGTH = 16;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final byte KEYSIZE_128_OFFSET = 0x00;
  public static final byte KEYSIZE_256_OFFSET = 0x01;
  public static final short TMP_ARRAY_SIZE = 300;
  private static final short RSA_KEY_SIZE = 256;
  public static final short CERT_CHAIN_MAX_SIZE = 2500;//First 2 bytes for length.
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final byte POWER_RESET_FALSE = (byte) 0xAA;
  public static final byte POWER_RESET_TRUE = (byte) 0x00;
  private static final short COMPUTED_HMAC_KEY_SIZE = 32;
  private static byte[] CMAC_KDF_CONSTANT_L;
  private static byte[] CMAC_KDF_CONSTANT_ZERO;

  private static KeyAgreement keyAgreement;

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

  private Signature kdf;
  public static byte[] resetFlag;

  private Signature hmacSignature;
  //For ImportwrappedKey operations.
  private KMRsaOAEPEncoding rsaOaepDecipher;
  private KMPoolManager poolMgr;

  private KMOperationImpl globalOperation;
  // Entropy
  private RandomData rng;

  private static KMAndroidSEProvider androidSEProvider = null;

  public static KMAndroidSEProvider getInstance() {
    return androidSEProvider;
  }

  public KMAndroidSEProvider() {
    initStatics();
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
    keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
    poolMgr = KMPoolManager.getInstance();
    poolMgr.initECKey(ecKeyPair);
    //RsaOAEP Decipher
    rsaOaepDecipher = new KMRsaOAEPEncoding(KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1);

    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);

    globalOperation = new KMOperationImpl(); 

    // Temporary transient array created to use locally inside functions.
    tmpArray = JCSystem.makeTransientByteArray(TMP_ARRAY_SIZE,
        JCSystem.CLEAR_ON_DESELECT);
    Util.arrayFillNonAtomic(tmpArray, (short) 0, TMP_ARRAY_SIZE, (byte) 0);
    // Random number generator initialisation.
    rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    androidSEProvider = this;
    resetFlag = JCSystem.makeTransientByteArray((short) 1,
        JCSystem.CLEAR_ON_RESET);
    resetFlag[0] = (byte) POWER_RESET_FALSE;
  }
  
  void initStatics() {
    CMAC_KDF_CONSTANT_L = new byte[] {
	    0x00, 0x00, 0x01, 0x00 };
    CMAC_KDF_CONSTANT_ZERO = new byte[] {0x00};
  }

  public void clean() {
    Util.arrayFillNonAtomic(tmpArray, (short) 0, TMP_ARRAY_SIZE, (byte) 0);
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
    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
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
    if (authDataLen != 0) {
      aesGcmCipher.updateAAD(authData, authDataStart, authDataLen);
    }
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
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength,
      byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacSign(key, data, dataStart, dataLength, mac, macStart);
  }
  
  @Override
  public short hmacSign(Object key,
      byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
	if(!(key instanceof KMHmacKey)) {
	  KMException.throwIt(KMError.INVALID_ARGUMENT);
	}
	KMHmacKey hmacKey = (KMHmacKey) key;
    return hmacSign(hmacKey.getKey(), data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public short hmacKDF(KMMasterKey masterkey, byte[] data, short dataStart,
      short dataLength, byte[] signature, short signatureStart) {
    try {
      KMAESKey aesKey = (KMAESKey) masterkey;
      short keyLen = (short) (aesKey.getKeySizeBits() / 8);
      aesKey.getKey(tmpArray, (short) 0);
      return hmacSign(tmpArray, (short) 0, keyLen, data, dataStart, dataLength,
          signature, signatureStart);
    } finally {
      clean();
    }
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
            if (digest == KMType.SHA1) { /* MGF Digest is SHA1 */
              return KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA1;
            } else if (digest == KMType.SHA2_256) { /* MGF Digest is SHA256 */
              return KMRsaOAEPEncoding.ALG_RSA_PKCS1_OAEP_SHA256_MGF1_SHA256;
            } else {
              KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
            }
          }
        }
        break;
    }
    return -1;
  }

  public KMOperation createSymmetricCipher(short alg, short purpose, short macLength,
      short blockMode, short padding, byte[] secret, short secretStart,
      short secretLength, byte[] ivBuffer, short ivStart, short ivLength,
      boolean isRkp) {

	  short cipherAlg = mapCipherAlg((byte) alg, (byte) padding, (byte) blockMode, (byte) 0);	  
	  KMOperation operation = null;
	  if (isRkp) {
	    operation = poolMgr.getRKpOperation(purpose, cipherAlg, alg, padding, blockMode, macLength);
	  } else {
	    operation = poolMgr.getOperationImpl(purpose, cipherAlg, alg, padding, blockMode, macLength, secretLength, false);
	  }
    // Get the KeyObject from the operation and update the key with the secret key material.
    KMKeyObject keyObj = operation.getKeyObject();
    Key key = (Key)keyObj.getKeyObjectInstance();
    switch (secretLength) {
      case 32:
      case 16:	  
        ((AESKey) key).setKey(secret, secretStart);
        break;
      case 24:
        ((DESKey) key).setKey(secret, secretStart);
        break;
      default:
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        break;
    } 
    ((KMOperationImpl) operation).init(key, KMType.INVALID_VALUE, ivBuffer, ivStart, ivLength);
    return operation;
  }

  public KMOperation createHmacSignerVerifier(short purpose, short digest,
      byte[] secret, short secretStart, short secretLength, boolean isRkp) {
    KMOperation operation = null;
    if (digest != KMType.SHA2_256) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (isRkp) {
      operation = poolMgr.getRKpOperation(purpose, Signature.ALG_HMAC_SHA_256, KMType.HMAC,
          KMType.INVALID_VALUE, KMType.INVALID_VALUE, KMType.INVALID_VALUE);
    } else {
      operation = poolMgr.getOperationImpl(purpose, Signature.ALG_HMAC_SHA_256,
          KMType.HMAC, KMType.INVALID_VALUE, KMType.INVALID_VALUE, KMType.INVALID_VALUE, (short)0, false);
    }
    // Get the KeyObject from the operation and update the key with the secret key material.
    KMKeyObject keyObj = operation.getKeyObject();
    HMACKey key = (HMACKey)keyObj.getKeyObjectInstance();
    key.setKey(secret, secretStart, secretLength);
    ((KMOperationImpl) operation).init(key, digest, null, (short) 0, (short) 0);
    return operation;
  }
  
  private KMOperation createHmacSignerVerifier(short purpose, short digest, HMACKey hmacKey, boolean isTrustedConf) {
    if (digest != KMType.SHA2_256) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    KMOperation operation =
      poolMgr.getOperationImpl(purpose, Signature.ALG_HMAC_SHA_256,
        KMType.HMAC, KMType.INVALID_VALUE, KMType.INVALID_VALUE, KMType.INVALID_VALUE, (short)0, isTrustedConf);
    // Get the KeyObject from the operation and update the key with the secret key material.
    KMKeyObject keyObj = operation.getKeyObject();
    HMACKey key = (HMACKey)keyObj.getKeyObjectInstance();
    short len = hmacKey.getKey(tmpArray, (short) 0);
    key.setKey(tmpArray, (short) 0, len);
    ((KMOperationImpl) operation).init(key, digest, null, (short) 0, (short) 0);
    return operation; 
  }

  @Override
  public KMOperation getRkpOperation(byte purpose, byte alg,
      byte digest, byte padding, byte blockMode, byte[] keyBuf, short keyStart,
      short keyLength, byte[] ivBuf, short ivStart, short ivLength,
      short macLength) {
    KMOperation opr = null;
    switch (alg) {
    case KMType.AES:
      // Convert macLength to bytes
      macLength = (short) (macLength / 8);
      opr = createSymmetricCipher(alg, purpose, macLength, blockMode, padding, keyBuf, keyStart, keyLength, ivBuf,
          ivStart, ivLength, true/* isRKP */);
      break;
    case KMType.HMAC:
      opr = createHmacSignerVerifier(purpose, digest, keyBuf, keyStart, keyLength, true/* isRKP */);
      break;
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return opr;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg,
      byte digest, byte padding, byte blockMode, byte[] keyBuf, short keyStart,
      short keyLength, byte[] ivBuf, short ivStart, short ivLength,
      short macLength) {
    KMOperation opr = null;
    switch (alg) {
      case KMType.AES:
      case KMType.DES:
        // Convert macLength to bytes
        macLength = (short) (macLength / 8);
        opr = createSymmetricCipher(alg, purpose, macLength, blockMode, padding, keyBuf, keyStart,
            keyLength, ivBuf, ivStart, ivLength, false/* isRKP */);
        break;
      case KMType.HMAC:
        opr = createHmacSignerVerifier(purpose, digest, keyBuf, keyStart, keyLength, false/* isRKP */);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return opr;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode,
	      Object key, byte interfaceType, byte[] ivBuf, short ivStart, short ivLength, short macLength,
	      boolean oneShot) {
    short keyLen = 0;
    globalOperation.setPurpose(purpose);
    globalOperation.setAlgorithmType(alg);
    globalOperation.setPaddingAlgorithm(padding);
    globalOperation.setBlockMode(blockMode);
    try {
      switch (interfaceType) {
        case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
	  KMAESKey aesKey = (KMAESKey) key;
	  keyLen = (short) (aesKey.getKeySizeBits() / 8);
	  aesKey.getKey(tmpArray, (short) 0);
	  break;
	
	default:
	  KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
	
      switch (alg) {
        case KMType.HMAC:
	  HMACKey hmackey = createHMACKey(tmpArray, (short)0, keyLen);
	  globalOperation.setSignature(hmacSignature);
	  globalOperation.init(hmackey, digest, null, (short)0, (short)0);
	  break;
	
	default:
	  KMException.throwIt(KMError.INVALID_ARGUMENT);  
      }  
    } finally {
      clean();
    }
    return globalOperation;
  }  

  @Override
  public KMOperation initTrustedConfirmationSymmetricOperation(KMComputedHmacKey computedHmacKey) {
    KMHmacKey key = (KMHmacKey) computedHmacKey;
    return createHmacSignerVerifier(KMType.VERIFY, KMType.SHA2_256, key.getKey(), true);
  } 
  
  public KMOperation createRsaSigner(short digest, short padding, byte[] secret,
      short secretStart, short secretLength, byte[] modBuffer, short modOff,
      short modLength) {
    byte alg = mapSignature256Alg(KMType.RSA, (byte) padding, (byte) digest);
    KMOperation operation = poolMgr.getOperationImpl(KMType.SIGN, alg, KMType.RSA, padding,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE, secretLength, false);
    // Get the KeyObject from the operation and update the key with the secret key material.
    KMKeyObject keyObj = operation.getKeyObject();
    RSAPrivateKey key = (RSAPrivateKey)((KeyPair)(keyObj.getKeyObjectInstance())).getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    ((KMOperationImpl) operation).init(key, digest, null, (short) 0, (short) 0);
    return operation;
  }

  public KMOperation createRsaDecipher(short padding, short mgfDigest, byte[] secret,
      short secretStart, short secretLength, byte[] modBuffer, short modOff,
      short modLength) {
    byte cipherAlg = mapCipherAlg(KMType.RSA, (byte) padding, (byte) 0, (byte) mgfDigest);
    KMOperation operation = poolMgr.getOperationImpl(KMType.DECRYPT, cipherAlg, KMType.RSA, padding,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE, secretLength, false); 
    // Get the KeyObject from the operation and update the key with the secret key material.
    KMKeyObject keyObj = operation.getKeyObject();
    RSAPrivateKey key = (RSAPrivateKey) ((KeyPair)(keyObj.getKeyObjectInstance())).getPrivate();
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    ((KMOperationImpl) operation).init(key, KMType.INVALID_VALUE, null, (short) 0, (short) 0);
    return operation;
  }

  public KMOperation createEcSigner(short digest, byte[] secret,
      short secretStart, short secretLength) {
    byte alg = mapSignature256Alg(KMType.EC, (byte) 0, (byte) digest);
    KMOperation operation = poolMgr
            .getOperationImpl(KMType.SIGN, alg, KMType.EC, KMType.INVALID_VALUE,
                KMType.INVALID_VALUE, KMType.INVALID_VALUE, secretLength, false);
    KMKeyObject keyObj = operation.getKeyObject();
    ECPrivateKey key = (ECPrivateKey) ((KeyPair)(keyObj.getKeyObjectInstance())).getPrivate();
    key.setS(secret, secretStart, secretLength);
    ((KMOperationImpl) operation).init(key, digest, null, (short) 0, (short) 0);
    return operation;
  }

  public KMOperation createKeyAgreement(byte[] secret, short secretStart,
      short secretLength) {
    KMOperation operation = poolMgr
        .getOperationImpl(KMType.AGREE_KEY, KeyAgreement.ALG_EC_SVDP_DH_PLAIN,
            KMType.EC, KMType.INVALID_VALUE, KMType.INVALID_VALUE, KMType.INVALID_VALUE, (short)0, false);
    KMKeyObject keyObj = operation.getKeyObject();
    ECPrivateKey key = (ECPrivateKey) ((KeyPair)(keyObj.getKeyObjectInstance())).getPrivate();
    key.setS(secret, secretStart, secretLength);
    ((KMOperationImpl) operation).init(key, KMType.INVALID_VALUE, null, (short) 0, (short) 0);
    return operation;
  }

  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg,
      byte padding, byte digest, byte mgfDigest, byte[] privKeyBuf, short privKeyStart,
      short privKeyLength, byte[] pubModBuf, short pubModStart,
      short pubModLength) {
    KMOperation opr = null;
    if (alg == KMType.RSA) {
      switch (purpose) {
        case KMType.SIGN:
          opr = createRsaSigner(digest, padding, privKeyBuf,
              privKeyStart, privKeyLength, pubModBuf, pubModStart, pubModLength);
          break;
        case KMType.DECRYPT:
          opr = createRsaDecipher(padding, mgfDigest, privKeyBuf,
              privKeyStart, privKeyLength, pubModBuf, pubModStart, pubModLength);
          break;
        default:
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          break;
      }
    } else if (alg == KMType.EC) {
      switch (purpose) {
        case KMType.SIGN:
          opr = createEcSigner(digest, privKeyBuf, privKeyStart, privKeyLength);
          break;

        case KMType.AGREE_KEY:
          opr = createKeyAgreement(privKeyBuf, privKeyStart, privKeyLength);
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
  public short cmacKDF(KMPreSharedKey pSharedKey, byte[] label,
      short labelStart, short labelLen, byte[] context, short contextStart,
      short contextLength, byte[] keyBuf, short keyStart) {
    HMACKey key = cmacKdf(pSharedKey, label, labelStart, labelLen, context,
        contextStart, contextLength);
    return key.getKey(keyBuf, keyStart);
  }

  @Override
  public boolean isUpgrading() {
    return UpgradeManager.isUpgrading();
  }

  @Override
  public KMMasterKey createMasterKey(KMMasterKey masterKey, short keySizeBits) {
    try {
      if (masterKey == null) {
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES,
            keySizeBits, false);
        masterKey = new KMAESKey(key);
        short keyLen = (short) (keySizeBits / 8);
        getTrueRandomNumber(tmpArray, (short) 0, keyLen);
        ((KMAESKey)masterKey).setKey(tmpArray, (short) 0);
      }
      return (KMMasterKey) masterKey;
    } finally {
      clean();
    }
  }

  @Override
  public KMPreSharedKey createPreSharedKey(KMPreSharedKey preSharedKey, byte[] keyData, short offset, short length) {
    short lengthInBits = (short) (length * 8);
    if ((lengthInBits % 8 != 0) || !(lengthInBits >= 64 && lengthInBits <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (preSharedKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, lengthInBits,
          false);
      preSharedKey = new KMHmacKey(key);
    }
    ((KMHmacKey)preSharedKey).setKey(keyData, offset, length);
    return (KMPreSharedKey) preSharedKey;
  }

  @Override
  public KMComputedHmacKey createComputedHmacKey(KMComputedHmacKey computedHmacKey, byte[] keyData, short offset, short length) {
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (computedHmacKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (length * 8),
          false);
      computedHmacKey = new KMHmacKey(key);
    }
    ((KMHmacKey)computedHmacKey).setKey(keyData, offset, length);
    return (KMComputedHmacKey) computedHmacKey;
  }  

  @Override
  public short ecSign256(byte[] secret, short secretStart, short secretLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {

    ECPrivateKey key = (ECPrivateKey) ecKeyPair.getPrivate();
    key.setS(secret, secretStart, secretLength);

    Signature.OneShot signer = null;
    try {

      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      signer.init(key, Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
          outputDataBuf, outputDataStart);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }

  @Override
  public short ecSign256(KMAttestationKey ecPrivKey, byte[] inputDataBuf, short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    Signature.OneShot signer = null;
    try {

      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      signer.init(((KMECPrivateKey) ecPrivKey).getPrivateKey(), Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
          outputDataBuf, outputDataStart);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }

  @Override
  public short rsaSign256Pkcs1(byte[] secret, short secretStart, short secretLength, byte[] modBuf,
      short modStart,
      short modLength, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart) {

    Signature.OneShot signer = null;
    try {

      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_RSA, Cipher.PAD_PKCS1);

      RSAPrivateKey key = (RSAPrivateKey) rsaKeyPair.getPrivate();
      ;
      key.setExponent(secret, secretStart, secretLength);
      key.setModulus(modBuf, modStart, modLength);

      signer.init(key, Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
          outputDataBuf, outputDataStart);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }

  }

  @Override
  public boolean isAttestationKeyProvisioned() {
    return false;
  }

  @Override
  public short getAttestationKeyAlgorithm() {
    return KMType.INVALID_VALUE;
  }


  @Override
  public short hkdf(byte[] ikm, short ikmOff, short ikmLen, byte[] salt,
      short saltOff, short saltLen, byte[] info, short infoOff, short infoLen,
      byte[] out, short outOff, short outLen) {
    // HMAC_extract
    hkdfExtract(ikm, ikmOff, ikmLen, salt, saltOff, saltLen, tmpArray, (short) 0);
    //HMAC_expand
    return hkdfExpand(tmpArray, (short) 0, (short) 32, info, infoOff, infoLen, out, outOff, outLen);
  }

  private short hkdfExtract(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff,
      short saltLen,
      byte[] out, short off) {
    // https://tools.ietf.org/html/rfc5869#section-2.2
    HMACKey hmacKey = createHMACKey(salt, saltOff, saltLen);
    hmacSignature.init(hmacKey, Signature.MODE_SIGN);
    return hmacSignature.sign(ikm, ikmOff, ikmLen, out, off);
  }

  private short hkdfExpand(byte[] prk, short prkOff, short prkLen, byte[] info, short infoOff,
      short infoLen,
      byte[] out, short outOff, short outLen) {
    // https://tools.ietf.org/html/rfc5869#section-2.3
    short digestLen = (short) 32; // SHA256 digest length.
    // Calculate no of iterations N.
    short n = (short) ((short) (outLen + digestLen - 1) / digestLen);
    if (n > 255) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    HMACKey hmacKey = createHMACKey(prk, prkOff, prkLen);
    Util.arrayFill(tmpArray, (short) 0, (short) 33, (byte) 0);
    short bytesCopied = 0;
    short len = 0;
    for (short i = 0; i < n; i++) {
      tmpArray[0]++;
      hmacSignature.init(hmacKey, Signature.MODE_SIGN);
      if (i != 0) {
        hmacSignature.update(tmpArray, (short) 1, (short) 32);
      }
      hmacSignature.update(info, infoOff, infoLen);
      len = hmacSignature.sign(tmpArray, (short) 0, (short) 1, tmpArray, (short) 1);
      if ((short) (bytesCopied + len) > outLen) {
        len = (short) (outLen - bytesCopied);
      }
      Util.arrayCopyNonAtomic(tmpArray, (short) 1, out, (short) (outOff + bytesCopied), len);
      bytesCopied += len;
    }
    return outLen;
  }

  @Override
  public short ecdhKeyAgreement(byte[] privKey, short privKeyOff,
      short privKeyLen, byte[] publicKey, short publicKeyOff,
      short publicKeyLen, byte[] secret, short secretOff) {
    keyAgreement.init(createEcKey(privKey, privKeyOff, privKeyLen));
    return keyAgreement.generateSecret(publicKey, publicKeyOff, publicKeyLen, secret, secretOff);
  }

  @Override
  public boolean ecVerify256(byte[] pubKey, short pubKeyOffset, short pubKeyLen,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] signatureDataBuf, short signatureDataStart,
      short signatureDataLen) {
    Signature.OneShot signer = null;
    try {
      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      ECPublicKey key = (ECPublicKey) ecKeyPair.getPublic();
      key.setW(pubKey, pubKeyOffset, pubKeyLen);
      signer.init(key, Signature.MODE_VERIFY);
      return signer.verify(inputDataBuf, inputDataStart, inputDataLength,
          signatureDataBuf, signatureDataStart,
          (short) (signatureDataBuf[(short) (signatureDataStart + 1)] + 2));
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }

  @Override
  public short ecSign256(KMDeviceUniqueKeyPair ecPrivKey, byte[] inputDataBuf,
      short inputDataStart, short inputDataLength, byte[] outputDataBuf,
      short outputDataStart) {
    Signature.OneShot signer = null;
    try {
      signer = Signature.OneShot.open(MessageDigest.ALG_SHA_256,
          Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL);
      signer.init(((KMECDeviceUniqueKey) ecPrivKey).getPrivateKey(), Signature.MODE_SIGN);
      return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
          outputDataBuf, outputDataStart);
    } finally {
      if (signer != null) {
        signer.close();
      }
    }
  }
  
  @Override
  public KMDeviceUniqueKeyPair createRkpDeviceUniqueKeyPair(KMDeviceUniqueKeyPair key,
      byte[] pubKey, short pubKeyOff, short pubKeyLen, byte[] privKey,
      short privKeyOff, short privKeyLen) {
    if (key == null) {
      KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      poolMgr.initECKey(ecKeyPair);
      key = new KMECDeviceUniqueKey(ecKeyPair);
    }
    ((KMECDeviceUniqueKey) key).setS(privKey, privKeyOff, privKeyLen);
    ((KMECDeviceUniqueKey) key).setW(pubKey, pubKeyOff, pubKeyLen);
    return (KMDeviceUniqueKeyPair) key;
  }

  @Override
  public KMRkpMacKey createRkpMacKey(KMRkpMacKey rkpMacKey, byte[] keyData,
      short offset, short length) {
    if (rkpMacKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (length * 8),
          false);
      rkpMacKey = new KMHmacKey(key);
    }
    ((KMHmacKey) rkpMacKey).setKey(keyData, offset, length);
    return rkpMacKey;
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
  
  public boolean isPowerReset() {
    boolean flag = false;
    if (resetFlag[0] == POWER_RESET_TRUE) {
      resetFlag[0] = POWER_RESET_FALSE;
      flag = true;
      if (poolMgr != null) {
        poolMgr.powerReset();
      }
    }
    return flag;
  }

  @Override
  public void onSave(Element element, byte interfaceType, Object object) {
    element.write(interfaceType);
    if (object == null) {
      element.write(null);
      return;
    }
    switch (interfaceType) {
      case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
        KMAESKey.onSave(element, (KMAESKey) object);
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY:
        KMHmacKey.onSave(element, (KMHmacKey) object);
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR:
        KMECDeviceUniqueKey.onSave(element, (KMECDeviceUniqueKey) object);
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY:
          KMHmacKey.onSave(element, (KMHmacKey) object);
          break;
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }
  
  @Override
  public Object onRestore(Element element) {
    if (element == null) {
      return null;
    }
    byte interfaceType = element.readByte();
    switch (interfaceType) {
      case KMDataStoreConstants.INTERFACE_TYPE_COMPUTED_HMAC_KEY:
        return KMHmacKey.onRestore((HMACKey) element.readObject());
      case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
        return KMAESKey.onRestore((AESKey) element.readObject());
      case KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY:
        return KMHmacKey.onRestore((HMACKey) element.readObject());
      case KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR:
        return KMECDeviceUniqueKey.onRestore((KeyPair) element.readObject());
      case KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY:
          return KMHmacKey.onRestore((HMACKey) element.readObject());
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return null;
  }
  
  @Override
  public short getBackupPrimitiveByteCount(byte interfaceType) {
    short primitiveCount = 1; // interface type
    switch (interfaceType) {
      case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
        primitiveCount += KMAESKey.getBackupPrimitiveByteCount();
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY:
        primitiveCount += KMHmacKey.getBackupPrimitiveByteCount();
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR:
        primitiveCount += KMECDeviceUniqueKey.getBackupPrimitiveByteCount();
        break;
      case KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY:
        primitiveCount += KMHmacKey.getBackupPrimitiveByteCount();
        break;
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return primitiveCount;
  }

  @Override
  public short getBackupObjectCount(byte interfaceType) {
    switch (interfaceType) {
      case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
        return KMAESKey.getBackupObjectCount();
      case KMDataStoreConstants.INTERFACE_TYPE_PRE_SHARED_KEY:
        return KMHmacKey.getBackupObjectCount();
      case KMDataStoreConstants.INTERFACE_TYPE_DEVICE_UNIQUE_KEY_PAIR:
        return KMECDeviceUniqueKey.getBackupObjectCount();
      case KMDataStoreConstants.INTERFACE_TYPE_RKP_MAC_KEY:
          return KMHmacKey.getBackupObjectCount();
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return 0;
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
  
}
