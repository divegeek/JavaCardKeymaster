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
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * Simulator only supports 512 bit RSA key pair, 128 AES Key, 128 bit 3Des key, less then 256 bit EC
 * Key, and upto 512 bit HMAC key. Also simulator does not support TRNG, so this implementation just
 * creates its own RNG using PRNG.
 */
public class KMSimulator implements KMSEProvider {

  public static final short AES_GCM_TAG_LENGTH = 12;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short MAX_RND_NUM_SIZE = 64;
  public static final short ENTROPY_POOL_SIZE = 16; // simulator does not support 256 bit aes keys
  public static final byte[] aesICV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  public static boolean jcardSim = false;

  private static KeyPair rsa512KeyPair;
  private static KeyPair ec192KeyPair;
  private static AESKey aes128Key;
  private static DESKey triDesKey;
  private static HMACKey hmac128Key;
  private static HMACKey hmac256Key;
  private static AEADCipher aesGcmCipher;
  private static AESKey derivedKey;
  private static Signature kdf;

  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;

  // Implements Oracle Simulator based restricted crypto provider
  public KMSimulator() {
    // Various Keys
    rsa512KeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
    ec192KeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
    aes128Key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    triDesKey =
        (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_2KEY, false);
    hmac128Key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) 128, false);
    hmac256Key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) 256, false);
    derivedKey =
        (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);

    // RNG
    rndNum = JCSystem.makeTransientByteArray(MAX_RND_NUM_SIZE, JCSystem.CLEAR_ON_RESET);
    entropyPool = JCSystem.makeTransientByteArray(ENTROPY_POOL_SIZE, JCSystem.CLEAR_ON_RESET);
    rngCounter = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_RESET);
    initEntropyPool(entropyPool);
    try {
      aesRngCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
    } catch (CryptoException exp) {
      ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
    }
    aesRngKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
  }

  public KeyPair createRsaKeyPair() {
    // By default 65537 is used as public exponent no need to set the public exponent. Now generate
    // 512 bit RSA keypair for the given exponent
    rsa512KeyPair.genKeyPair();
    return rsa512KeyPair;
  }

  public KeyPair createECKeyPair() {
    // Simulator does not support 256 bit keys.
    // Generate default 192 bit key pair supported by simulator.
    ec192KeyPair.genKeyPair();
    return ec192KeyPair;
  }

  public AESKey createAESKey(short keysize) {
    // keysize is ignored as simulator only supports 128 bit aes key
    newRandomNumber(rndNum, (short) 0, (short) 16);
    aes128Key.setKey(rndNum, (short) 0);
    return aes128Key;
  }

  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    if (length > 16) length = 16;
    else if(length < 16) return null;
    aes128Key.setKey(buf, startOff);
    return aes128Key;
  }

  public DESKey createTDESKey() {
    // only 128 bit keys are supported
    newRandomNumber(rndNum, (short) 0, (short) 21);
    triDesKey.setKey(rndNum, (short) 0);
    return triDesKey;
  }

  public HMACKey createHMACKey(short keysize) {
    // simulator only supports HMAC keys for SHA1 and SHA256 with block size 64.
    // So only 128 and 256 bit HMAC keys are supported.
    HMACKey key;
    if (keysize == 128) {
      key = hmac128Key;
      keysize = 16;
    } else if (keysize == 256) {
      key = hmac256Key;
      keysize = 32;
    } else {
      key = hmac128Key; // by default the simulator will return 128 bit keys for SHA1
      keysize = 16;
    }
    newRandomNumber(rndNum, (short) 0, keysize);
    key.setKey(rndNum, (short) 0, keysize);
    return key;
  }

  @Override
  public short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff) {
    return 0;
  }

  @Override
  public void createAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart, short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength, short[] lengths) {

  }

  @Override
  public boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff, short length) {
    return false;
  }

  @Override
  public boolean importAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart, short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {
    return false;
  }

  @Override
  public void addRngEntropy(byte[] num, short offset, short length) {
    // Maximum length can be 256 bytes. But currently we support max 32 bytes seed.
    // Get existing entropy pool.
    if (length > 32) length = 32;
    // Create new temporary pool.
    // Populate the new pool with the entropy which is derived from current entropy pool.
    newRandomNumber(rndNum, (short) 0, (short) entropyPool.length);
    // Copy the entropy to the current pool - updates the entropy pool.
    Util.arrayCopy(rndNum, (short) 0, entropyPool, (short) 0, (short) entropyPool.length);
    short index = 0;
    short randIndex = 0;
    // XOR the seed received from the master in the entropy pool - 16 bytes (entPool.length).
    // at a time.
    while (index < length) {
      entropyPool[randIndex] = (byte) (entropyPool[randIndex] ^ num[(short) (offset + index)]);
      randIndex++;
      index++;
      if (randIndex >= entropyPool.length) {
        randIndex = 0;
      }
    }
  }

  @Override
  public short aesGCMEncrypt(
      byte[] aesKey,
      short keyStart,
      short keyLen,
      byte[] secret,
      short secretStart,
      short secretLen,
      byte[] encSecret,
      short encSecretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
    if (jcardSim) return -1;
    if(authTagLen != AES_GCM_TAG_LENGTH){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if(nonceLen != AES_GCM_NONCE_LENGTH){
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    }
    byte[] aad = JCSystem.makeTransientByteArray(authDataLen, JCSystem.CLEAR_ON_RESET);
    Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
    AESKey key = createAESKey(aesKey, keyStart, keyLen);
    try {
      aesGcmCipher.init(key, Cipher.MODE_ENCRYPT, nonce, nonceStart, nonceLen);
    } catch (CryptoException exp) {
      KMException.throwIt(exp.getReason());
    }
    // add the auth data
    try {
      aesGcmCipher.updateAAD(aad, (short) 0, authDataLen);
    } catch (CryptoException exp) {
      KMException.throwIt(exp.getReason());
    }
    // encrypt the secret
    short ciphLen = aesGcmCipher.doFinal(secret, secretStart, secretLen, encSecret, encSecretStart);
    // The tag buffer must be exact size otherwise simulator returns 0 tag.
    byte[] tag = JCSystem.makeTransientByteArray(AES_GCM_TAG_LENGTH, JCSystem.CLEAR_ON_RESET);
    aesGcmCipher.retrieveTag(tag, (short) 0, AES_GCM_TAG_LENGTH);
    Util.arrayCopyNonAtomic(tag,(short)0, authTag, authTagStart,AES_GCM_TAG_LENGTH);
    return ciphLen;
/*    aesGcmCipher.init(key, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
    try {
      aesGcmCipher.updateAAD(aad, (short) 0, authDataLen);
    } catch (CryptoException exp) {
      KMException.throwIt(exp.getReason());
    }
    byte[] plain = JCSystem.makeTransientByteArray(secretLen, JCSystem.CLEAR_ON_RESET);
    // encrypt the secret
    ciphLen = aesGcmCipher.doFinal(encSecret, encSecretStart, ciphLen, plain, (short) 0);
    boolean ver = aesGcmCipher.verifyTag(tag, (short) 0, (short) 12, (short) 12);
    if (ver == true) {
      KMException.throwIt((short) 10);
    } else {
      KMException.throwIt((short) 20);
    }
    return 0;
 */
  }

  public boolean aesGCMDecrypt(
    byte[] aesKey,
    short keyStart,
    short keyLen,
    byte[] encSecret,
      short encSecretStart,
      short encSecretLen,
      byte[] secret,
      short secretStart,
      byte[] nonce,
      short nonceStart,
      short nonceLen,
      byte[] authData,
      short authDataStart,
      short authDataLen,
      byte[] authTag,
      short authTagStart,
      short authTagLen) {
    if(jcardSim) return true;
    if (aesGcmCipher == null) {
      aesGcmCipher = (AEADCipher) Cipher.getInstance(AEADCipher.ALG_AES_GCM, false);
    }
    // allocate aad buffer of exact size - otherwise simulator throws exception
    byte[] aad = JCSystem.makeTransientByteArray(authDataLen, JCSystem.CLEAR_ON_RESET);
    Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
    // allocate tag of exact size.
    byte[] tag = JCSystem.makeTransientByteArray(AES_GCM_TAG_LENGTH, JCSystem.CLEAR_ON_RESET);
    Util.arrayCopyNonAtomic(authTag, authTagStart, tag, (short) 0, authTagLen);
    boolean verification = false;
    AESKey key = createAESKey(aesKey, keyStart, keyLen);
    try {
      aesGcmCipher.init(key, Cipher.MODE_DECRYPT, nonce, nonceStart, nonceLen);
      aesGcmCipher.updateAAD(aad, (short) 0, authDataLen);
      //byte[] plain = JCSystem.makeTransientByteArray(encSecretLen, JCSystem.CLEAR_ON_RESET);
      // encrypt the secret
      aesGcmCipher.doFinal(encSecret, encSecretStart, encSecretLen, secret, secretStart);
      verification = aesGcmCipher.verifyTag(tag, (short) 0, (short) 12, (short) 12);
    } catch (CryptoException exp) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return verification;
  }

  @Override
  public byte[] getTrueRandomNumber(short i) {
    // ignore the size as simulator only supports 128 bit entropy
    return entropyPool;
  }

  @Override
  public short aesCCMSign(
      byte[] bufIn,
      short bufInStart,
      short buffInLength,
      byte[] masterKeySecret,
      byte[] bufOut,
      short bufStart) {
    if (masterKeySecret.length > 16) {

      return -1;
    }
    aes128Key.setKey(masterKeySecret, (short) 0);
    kdf.init(aes128Key, Signature.MODE_SIGN);
    return kdf.sign(bufIn, bufInStart, buffInLength, bufOut, bufStart);
  }

  public ECPrivateKey createEcPrivateKey(byte[] pubBuffer, short pubOff, short pubLength,
                                         byte[] privBuffer, short privOff, short privLength) {
    // Simulator does not support NamedParameterSpec or 256 bit keys
    ECPrivateKey privKey = (ECPrivateKey) ec192KeyPair.getPrivate();
    if(privLength > 24){
      privLength = 24;// simulator does not support more then 24 bytes - 192 bit key.
    }else if(privLength <= 20){
      return null;
    }
    privKey.setS(privBuffer,privOff, privLength);
    return privKey;
  }

  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
    // simulator only supports HMAC keys for SHA1 and SHA256 with block size 64.
    // So only 128 and 256 bit HMAC keys are supported.
    HMACKey key;
    if (secretLength == 16) {
      key = hmac128Key;
      key.setKey(secretBuffer, secretOff, secretLength);
    } else if (secretLength == 32) {
      key = hmac256Key;
      key.setKey(secretBuffer, secretOff, secretLength);
    } else {
      key = hmac128Key; // by default the simulator will return 128 bit keys for SHA1
      key.setKey(secretBuffer, secretOff, (short)16);
    }
    return key;
  }
  public DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength) {
    // only 128 bit keys are supported
    if(secretLength < 128) return null;
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }

  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength, byte[] privBuffer, short privOff, short privLength) {
    return null;
  }

  public HMACKey cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength) {
    return null;
  }

  @Override
  public short cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength, byte[] keyBuf, short keyStart) {
    return 0;
  }

  public short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    return 0;
  }

  public boolean hmacVerify(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart, short macLength) {
    return false;
  }

  @Override
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    return 0;
  }

  @Override
  public boolean hmacVerify(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart, short macLength) {
    return false;
  }

  @Override
  public short rsaDecipherOAEP256(byte[] secret, short secretStart, short secretLength, byte[] modBuffer, short modOff, short modLength, byte[] inputDataBuf, short inputDataStart, short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    return 0;
  }

  @Override
  public short rsaSignPKCS1256(byte[] secret, short secretStart, short secretLength, byte[] modBuffer, short modOff, short modLength, byte[] inputDataBuf, short inputDataStart, short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    return 0;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode, byte[] keyBuf, short keyStart, short keyLength, byte[] ivBuf, short ivStart, short ivLength, short macLength) {
    return null;
  }

  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest, byte[] privKeyBuf, short privKeyStart, short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {
    return null;
  }

  public RSAPrivateKey createRsaPrivateKey(byte[] modBuffer, short modOff, short modLength, byte[] privBuffer, short privOff, short privLength) {
    RSAPrivateKey privKey = (RSAPrivateKey) rsa512KeyPair.getPrivate();
    if(privLength > 64) privLength = 64;
    else if(privLength < 64)return null;
    if(modLength > 64) modLength = 64;
    else if( modLength < 64) return null;
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;
  }

  private void initEntropyPool(byte[] pool) {
    byte index = 0;
    RandomData trng;
    while (index < rngCounter.length) {
      rngCounter[index++] = 0;
    }
    try {
      trng = RandomData.getInstance(RandomData.ALG_TRNG);
      trng.nextBytes(pool, (short) 0, (short) pool.length);
    } catch (CryptoException exp) {
      if (exp.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
        // TODO change this when possible
        // simulator does not support TRNG algorithm. So, PRNG algorithm (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        trng.nextBytes(pool, (short) 0, (short) pool.length);
      } else {
        // TODO change this to proper error code
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }
  }

  // Generate a secure random number from existing entropy pool. This uses aes ecb algorithm with
  // 8 byte rngCounter and 16 byte block size.
  @Override
  public void newRandomNumber(byte[] num, short startOff, short length) {
    KMRepository repository = KMRepository.instance();
    byte[] bufPtr = repository.getHeap();
    short countBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short randBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short len = KMKeymasterApplet.AES_BLOCK_SIZE;
    aesRngKey.setKey(entropyPool, (short) 0);
    aesRngCipher.init(aesRngKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0, (short) 16);
    while (length > 0) {
      if (length < len) len = length;
      // increment rngCounter by one
      incrementCounter();
      // copy the 8 byte rngCounter into the 16 byte rngCounter buffer.
      Util.arrayCopy(rngCounter, (short) 0, bufPtr, countBufInd, (short) rngCounter.length);
      // encrypt the rngCounter buffer with existing entropy which forms the aes key.
      aesRngCipher.doFinal(
          bufPtr, countBufInd, KMKeymasterApplet.AES_BLOCK_SIZE, bufPtr, randBufInd);
      // copy the encrypted rngCounter block to buffer passed in the argument
      Util.arrayCopy(bufPtr, randBufInd, num, startOff, len);
      length = (short) (length - len);
      startOff = (short) (startOff + len);
    }
  }

  // increment 8 byte rngCounter by one
  private void incrementCounter() {
    // start with least significant byte
    short index = (short) (rngCounter.length - 1);
    while (index >= 0) {
      // if the msb of current byte is set then it will be negative
      if (rngCounter[index] < 0) {
        // then increment the rngCounter
        rngCounter[index]++;
        // is the msb still set? i.e. no carry over
        if (rngCounter[index] < 0) break; // then break
        else index--; // else go to the higher order byte
      } else {
        // if msb is not set then increment the rngCounter
        rngCounter[index]++;
        break;
      }
    }
  }

  @Override
  public short getSystemTimeInMilliSeconds(byte[] timeBuf, short timeStart, short timeOffset) {
    return 0;
  }

  @Override
  public short addListener(KMEventListener listener, byte eventType) {
    return 0;
  }

  @Override
  public short getEventData(byte[] eventBuf, short eventStart, short eventLength) {
    return 0;
  }

  @Override
  public boolean isAlgSupported(byte alg) {
    return false;
  }

  @Override
  public boolean isKeySizeSupported(byte alg, short keySize) {
    return false;
  }

  @Override
  public boolean isCurveSupported(byte eccurve) {
    return false;
  }

  @Override
  public boolean isDigestSupported(byte alg, byte digest) {
    return false;
  }

  @Override
  public boolean isPaddingSupported(byte alg, byte padding) {
    return false;
  }

  @Override
  public boolean isBlockModeSupported(byte alg, byte blockMode) {
    return false;
  }

  @Override
  public boolean isSystemTimerSupported() {
    return false;
  }

  @Override
  public boolean isBootEventSupported() {
    return false;
  }

}
