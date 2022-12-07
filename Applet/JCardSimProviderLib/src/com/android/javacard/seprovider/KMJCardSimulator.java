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

package com.android.javacard.seprovider;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
import javacard.security.KeyAgreement;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.globalplatform.upgrade.Element;

/**
 * Simulator only supports 512 bit RSA key pair, 128 AES Key, 128 bit 3Des key, less then 256 bit EC
 * Key, and upto 512 bit HMAC key. Also simulator does not support TRNG, so this implementation just
 * creates its own RNG using PRNG.
 */
public class KMJCardSimulator implements KMSEProvider {
  public static final short AES_GCM_TAG_LENGTH = 16;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short MAX_RND_NUM_SIZE = 64;
  public static final short ENTROPY_POOL_SIZE = 16; // simulator does not support 256 bit aes keys
  public static final byte[] aesICV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  private static final short RSA_KEY_SIZE = 256;
  public static final byte POWER_RESET_FALSE = (byte)0xAA;
  public static final byte POWER_RESET_TRUE = (byte)0x00;
  public static final byte AES_BLOCK_SIZE = 16;
  private static final short COMPUTED_HMAC_KEY_SIZE = 32;

  public static byte[] resetFlag;
  private static Signature hmacSignature;
  private static KeyAgreement keyAgreement;

  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;
  private KMHmacKey preSharedKey;
  // Below two flags are added for Functional test.
  public static boolean isDeviceRebooted = false;
  public static boolean isBootEventSignalSupported = false;


  private static KMJCardSimulator jCardSimulator = null;

  public static KMJCardSimulator getInstance() {
    return jCardSimulator;
  }

  // Implements Oracle Simulator based restricted crypto provider
  public KMJCardSimulator() {
    // Various Keys
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
    keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
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
    // various ciphers
    jCardSimulator = this;
    resetFlag = new byte[1];
    resetFlag[0] = (byte) POWER_RESET_FALSE;
  }


  public KeyPair createRsaKeyPair() {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    rsaKeyPair.genKeyPair();
    return rsaKeyPair;
  }


  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength,
      byte[] privBuffer, short privOff, short privLength) {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    RSAPrivateKey privKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;

  }


  public KeyPair createECKeyPair() {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ecKeyPair.genKeyPair();
    return ecKeyPair;
  }


  public ECPrivateKey createEcKey(byte[] privBuffer, short privOff, short privLength) {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    privKey.setS(privBuffer, privOff, privLength);
    return privKey;
  }


  public AESKey createAESKey(short keysize) {
    byte[] rndNum = new byte[(short) (keysize / 8)];
    return createAESKey(rndNum, (short) 0, (short) rndNum.length);
  }

  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    AESKey key = null;
    short keysize = (short) (length * 8);
    if (keysize == 128) {
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
      key.setKey(buf, (short) startOff);
    } else if (keysize == 256) {
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
      key.setKey(buf, (short) startOff);
    }
    return key;
  }


  public DESKey createTDESKey() {
    byte[] rndNum = new byte[24];
    newRandomNumber(rndNum, (short) 0, (short) rndNum.length);
    return createTDESKey(rndNum, (short) 0, (short) rndNum.length);
  }


  public DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength) {
    DESKey triDesKey =
        (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }


  public HMACKey createHMACKey(short keysize) {
    if ((keysize % 8 != 0) || !(keysize >= 64 && keysize <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] rndNum = new byte[(short) (keysize / 8)];
    newRandomNumber(rndNum, (short) 0, (short) (keysize / 8));
    return createHMACKey(rndNum, (short) 0, (short) rndNum.length);
  }

  @Override
  public short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff) {
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
  public void createAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf, short pubModStart, short pubModLength, short[] lengths) {
    switch (alg) {
      case KMType.RSA:
        if (RSA_KEY_SIZE != privKeyLength || RSA_KEY_SIZE != pubModLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        KeyPair rsaKey = createRsaKeyPair();
        RSAPrivateKey privKey = (RSAPrivateKey) rsaKey.getPrivate();
        //Copy exponent.
        byte[] exp = new byte[RSA_KEY_SIZE];
        lengths[0] = privKey.getExponent(exp, (short) 0);
        if (lengths[0] > privKeyLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayFillNonAtomic(privKeyBuf, privKeyStart, privKeyLength, (byte) 0);
        Util.arrayCopyNonAtomic(exp, (short) 0,
            privKeyBuf, (short) (privKeyStart + privKeyLength - lengths[0]), lengths[0]);
        //Copy modulus
        byte[] mod = new byte[RSA_KEY_SIZE];
        lengths[1] = privKey.getModulus(mod, (short) 0);
        if (lengths[1] > pubModLength) {
          CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayFillNonAtomic(pubModBuf, pubModStart, pubModLength, (byte) 0);
        Util.arrayCopyNonAtomic(mod, (short) 0,
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
  public boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff,
      short length) {
    switch (alg) {
      case KMType.AES:
        AESKey aesKey = createAESKey(buf, startOff, length);
        break;
      case KMType.DES:
        DESKey desKey = createTDESKey(buf, startOff, length);
        break;
      case KMType.HMAC:
        HMACKey hmacKey = createHMACKey(buf, startOff, length);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return true;
  }

  @Override
  public boolean importAsymmetricKey(byte alg, byte[] privKeyBuf, short privKeyStart,
      short privKeyLength, byte[] pubModBuf, short pubModStart, short pubModLength) {
    switch (alg) {
      case KMType.RSA:
        RSAPrivateKey rsaKey = createRsaKey(pubModBuf, pubModStart, pubModLength, privKeyBuf,
            privKeyStart, privKeyLength);
        break;
      case KMType.EC:
        ECPrivateKey ecPrivKey = createEcKey(privKeyBuf, privKeyStart, privKeyLength);
        break;
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    return true;
  }


  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
    HMACKey key = null;
    key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
        KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
    key.setKey(secretBuffer, secretOff, secretLength);
    return key;
  }

  @Override
  public short aesGCMEncrypt(
      byte[] keyBuf,
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
    //Create the sun jce compliant aes key
    if (keyLen != 32 && keyLen != 16) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    java.security.Key aesKey = new SecretKeySpec(keyBuf, keyStart, keyLen, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce, nonceStart,
        AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
      cipher.updateAAD(aad);
    }
    // Encrypt secret
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(secretLen)];
    try {
      len = (short) (cipher.doFinal(secret, secretStart, secretLen, outputBuf, (short) 0));
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Extract Tag appended at the end.
    Util.arrayCopyNonAtomic(outputBuf, (short) (len - AES_GCM_TAG_LENGTH), authTag, authTagStart,
        AES_GCM_TAG_LENGTH);
    //Copy the encrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short) 0, encSecret, encSecretStart,
        (short) (len - AES_GCM_TAG_LENGTH));
    return (short) (len - AES_GCM_TAG_LENGTH);
  }

  public boolean aesGCMDecrypt(
      byte[] keyBuf,
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
    // Create the sun jce compliant aes key
    if (keyLen != 32 && keyLen != 16) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    java.security.Key aesKey = new SecretKeySpec(keyBuf, keyStart, keyLen,
        "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    if (nonceLen != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(nonce, nonceStart, iv, (short) 0,
        AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(authTagLen * 8, nonce,
        nonceStart, AES_GCM_NONCE_LENGTH);
    try {
      cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    if (authDataLen != 0) {
      // Create auth data
      byte[] aad = new byte[authDataLen];
      Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0,
        authDataLen);
      cipher.updateAAD(aad);
    }
    // Append the auth tag at the end of data
    byte[] inputBuf = new byte[(short) (encSecretLen + authTagLen)];
    Util.arrayCopyNonAtomic(encSecret, encSecretStart, inputBuf, (short) 0,
        encSecretLen);
    Util.arrayCopyNonAtomic(authTag, authTagStart, inputBuf, encSecretLen,
        authTagLen);
    // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize((short) inputBuf.length)];
    try {
      len = (short) (cipher.doFinal(inputBuf, (short) 0,
          (short) inputBuf.length, outputBuf, (short) 0));
    } catch (AEADBadTagException e) {
      e.printStackTrace();
      return false;
    } catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy the decrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short) 0, secret, secretStart, len);
    return true;
  }

  @Override
  public void getTrueRandomNumber(byte[] buf, short start, short length) {
    newRandomNumber(buf, start, length);
  }

  public HMACKey cmacKdf(byte[] keyMaterial, short keyMaterialStart, short keyMaterialLen,
      byte[] label,
      short labelStart, short labelLen, byte[] context, short contextStart, short contextLength) {
    // This is hardcoded to requirement - 32 byte output with two concatenated 16 bytes K1 and K2.
    final byte n = 2; // hardcoded
    final byte[] L = {0, 0, 1,
        0}; // [L] 256 bits - hardcoded 32 bits as per reference impl in keymaster.
    final byte[] zero = {0}; // byte
    byte[] iBuf = new byte[]{0, 0, 0, 0}; // [i] counter - 32 bits
    byte[] keyOut = new byte[(short) (n * 16)];
    Signature prf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    AESKey key = (AESKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
    key.setKey(keyMaterial, keyMaterialStart);
    prf.init(key, Signature.MODE_SIGN);
    byte i = 1;
    short pos = 0;
    while (i <= n) {
      iBuf[3] = i;
      prf.update(iBuf, (short) 0, (short) 4); // 4 bytes of iBuf with counter in it
      prf.update(label, labelStart, labelLen); // label
      prf.update(zero, (short) 0, (short) 1); // 1 byte of 0x00
      prf.update(context, contextStart, contextLength); // context
      pos = prf.sign(L, (short) 0, (short) 4, keyOut, pos); // 4 bytes of L - signature of 16 bytes
      i++;
    }
    return createHMACKey(keyOut, (short) 0, (short) keyOut.length);
  }

  @Override
  public short cmacKDF(KMPreSharedKey pSharedKey, byte[] label,
      short labelStart, short labelLen, byte[] context, short contextStart, short contextLength,
      byte[] keyBuf, short keyStart) {
    KMHmacKey key = (KMHmacKey) pSharedKey;
    short keyMaterialLen = key.hmacKey.getSize();
    keyMaterialLen = (short) (keyMaterialLen / 8);
    short keyMaterialStart = 0;
    byte[] keyMaterial = new byte[keyMaterialLen];
    key.hmacKey.getKey(keyMaterial, keyMaterialStart);
    HMACKey hmacKey = cmacKdf(keyMaterial, keyMaterialStart, keyMaterialLen, label, labelStart,
        labelLen, context, contextStart, contextLength);
    return hmacKey.getKey(keyBuf, keyStart);
  }


  public short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac,
      short macStart) {
    hmacSignature.init(key, Signature.MODE_SIGN);
    return hmacSignature.sign(data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public short hmacKDF(KMMasterKey masterkey, byte[] data, short dataStart,
      short dataLength, byte[] signature, short signatureStart) {
    KMAESKey aesKey = (KMAESKey) masterkey;
    short keyLen = (short) (aesKey.aesKey.getSize() / 8);
    byte[] keyData = new byte[keyLen];
    aesKey.aesKey.getKey(keyData, (short) 0);
    return hmacSign(keyData, (short) 0, keyLen, data, dataStart, dataLength,
        signature, signatureStart);
  }

  @Override
  public short hkdf(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff, short saltLen,
                    byte[] info, short infoOff, short infoLen, byte[] out, short outOff, short outLen) {
    // HMAC_extract
    byte[] prk = new byte[32];
    hkdfExtract(ikm, ikmOff, ikmLen, salt, saltOff, saltLen, prk, (short) 0);
    //HMAC_expand
    return hkdfExpand(prk, (short) 0, (short) 32, info, infoOff, infoLen, out, outOff, outLen);
  }

  private short hkdfExtract(byte[] ikm, short ikmOff, short ikmLen, byte[] salt, short saltOff, short saltLen,
                            byte[] out, short off) {
    // https://tools.ietf.org/html/rfc5869#section-2.2
    HMACKey hmacKey = createHMACKey(salt, saltOff, saltLen);
    hmacSignature.init(hmacKey, Signature.MODE_SIGN);
    return hmacSignature.sign(ikm, ikmOff, ikmLen, out, off);
  }

  private short hkdfExpand(byte[] prk, short prkOff, short prkLen, byte[] info, short infoOff, short infoLen,
                           byte[] out, short outOff, short outLen) {
    // https://tools.ietf.org/html/rfc5869#section-2.3
    short digestLen = (short) 32; // SHA256 digest length.
    // Calculate no of iterations N.
    short n = (short) ((outLen + digestLen - 1) / digestLen);
    if (n > 255) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    HMACKey hmacKey = createHMACKey(prk, prkOff, prkLen);
    byte[] previousOutput = new byte[32]; // Length of output 32.
    byte[] cnt = {(byte) 0};
    short bytesCopied = 0;
    short len = 0;
    for (short i = 0; i < n; i++) {
      cnt[0]++;
      hmacSignature.init(hmacKey, Signature.MODE_SIGN);
      if (i != 0)
        hmacSignature.update(previousOutput, (short) 0, (short) 32);
      hmacSignature.update(info, infoOff, infoLen);
      len = hmacSignature.sign(cnt, (short) 0, (short) 1, previousOutput, (short) 0);
      if ((short) (bytesCopied + len) > outLen) {
        len = (short) (outLen - bytesCopied);
      }
      Util.arrayCopyNonAtomic(previousOutput, (short) 0, out, (short) (outOff + bytesCopied), len);
      bytesCopied += len;
    }
    return outLen;
  }

  @Override
  public short ecdhKeyAgreement(byte[] privKey, short privKeyOff, short privKeyLen, byte[] publicKey, short publicKeyOff,
                                short publicKeyLen, byte[] secret, short secretOff) {
    keyAgreement.init(createEcKey(privKey, privKeyOff, privKeyLen));
    return keyAgreement.generateSecret(publicKey, publicKeyOff, publicKeyLen, secret, secretOff);
  }

  @Override
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength, byte[] data,
      short dataStart, short dataLength, byte[] mac, short macStart) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacSign(key, data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public short hmacSign(Object key, byte[] data, short dataStart, short dataLength,
      byte[] signature, short signatureStart) {
    if(!(key instanceof KMHmacKey)) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    KMHmacKey hmacKey = (KMHmacKey) key;
    return hmacSign(hmacKey.hmacKey, data, dataStart, dataLength, signature, signatureStart);
  }

  @Override
  public boolean hmacVerify(KMComputedHmacKey key, byte[] data, short dataStart, 
    short dataLength, byte[] mac, short macStart, short macLength) {
    KMHmacKey hmacKey = (KMHmacKey) key;
    hmacSignature.init(hmacKey.hmacKey, Signature.MODE_VERIFY);
    return hmacSignature.verify(data, dataStart, dataLength, mac, macStart, macLength);
  }

  @Override
  public short rsaDecipherOAEP256(byte[] secret, short secretStart, short secretLength,
      byte[] modBuffer, short modOff, short modLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    KMCipher cipher = createRsaDecipher(
        KMType.RSA_OAEP, KMType.SHA1, secret, secretStart, secretLength, modBuffer, modOff,
        modLength);
    return cipher.doFinal(
        inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding,
      byte blockMode,
      byte[] keyBuf, short keyStart, short keyLength,
      byte[] ivBuf, short ivStart, short ivLength, short macLength) {
    switch (alg) {
      case KMType.AES:
      case KMType.DES:
        if (blockMode != KMType.GCM) {
          KMCipher cipher = createSymmetricCipher(alg, purpose, blockMode, padding, keyBuf,
              keyStart, keyLength,
              ivBuf, ivStart, ivLength);
          return new KMOperationImpl(cipher);
        } else {
          KMCipher aesGcm = createAesGcmCipher(purpose, macLength, keyBuf, keyStart, keyLength,
              ivBuf, ivStart, ivLength);
          return new KMOperationImpl(aesGcm);
        }
      case KMType.HMAC:
        Signature signerVerifier = createHmacSignerVerifier(purpose, digest, keyBuf, keyStart,
            keyLength);
        return new KMOperationImpl(signerVerifier);
      default:
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    return null;
  }

  @Override
  public KMOperation initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode,
	      Object key, byte interfaceType, byte[] ivBuf, short ivStart, short ivLength, short macLength,
	      boolean oneShot) {
    KMOperationImpl operation = null;
    short keyLen = 0;
    byte[] keyData = null;
   
    switch (interfaceType) {
      case KMDataStoreConstants.INTERFACE_TYPE_MASTER_KEY:
        KMAESKey aesKey = (KMAESKey) key;
    	keyLen = (short) (aesKey.aesKey.getSize() / 8);
        keyData = new byte[keyLen];
        aesKey.aesKey.getKey(keyData, (short) 0);
        break;

      default:
        KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    switch (alg){
      case KMType.HMAC:
        Signature signerVerifier = createHmacSignerVerifier(purpose, digest, keyData, (short)0,
    	            keyLen);
        operation =  new KMOperationImpl(signerVerifier);
        break;

      default:
        KMException.throwIt(KMError.INVALID_ARGUMENT);  
    }
    return operation;    
  }

  @Override
  public KMOperation initTrustedConfirmationSymmetricOperation(KMComputedHmacKey computedHmacKey) {
    KMHmacKey key = (KMHmacKey) computedHmacKey;
    Signature signerVerifier = createHmacSignerVerifier(KMType.VERIFY, KMType.SHA2_256, key.hmacKey);
    return new KMOperationImpl(signerVerifier);
  }
  
  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest,
      byte mgfDigest, byte[] privKeyBuf, short privKeyStart, short privKeyLength,
      byte[] pubModBuf, short pubModStart, short pubModLength) {
    if (alg == KMType.RSA) {
      switch (purpose) {
        case KMType.SIGN:
          Signature signer =
              createRsaSigner(
                  digest,
                  padding,
                  privKeyBuf,
                  privKeyStart,
                  privKeyLength,
                  pubModBuf,
                  pubModStart,
                  pubModLength);
          return new KMOperationImpl(signer);
        case KMType.DECRYPT:
          KMCipher decipher =
              createRsaDecipher(
                  padding, mgfDigest, privKeyBuf, privKeyStart, privKeyLength, pubModBuf, pubModStart,
                  pubModLength);
          return new KMOperationImpl(decipher);
        default:
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
      }
    } else if (alg == KMType.EC) {
      switch (purpose) {
        case KMType.SIGN:
          Signature signer =
              createEcSigner(digest, privKeyBuf, privKeyStart, privKeyLength);
          return new KMOperationImpl(signer);
        case KMType.AGREE_KEY:
          KeyAgreement keyAgreement =
              createKeyAgreement(privKeyBuf, privKeyStart, privKeyLength);
          return new KMOperationImpl(keyAgreement);
        default:
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
      }
    }
    CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    return null;
  }

  public KMCipher createRsaDecipher(short padding, short digest, byte[] secret, short secretStart,
      short secretLength, byte[] modBuffer, short modOff, short modLength) {
    byte cipherAlg = mapCipherAlg(KMType.RSA, (byte) padding, (byte) 0);
    if (cipherAlg == Cipher.ALG_RSA_PKCS1_OAEP) {
      return createRsaOAEP256Cipher(KMType.DECRYPT, (byte) digest, secret, secretStart,
          secretLength, modBuffer, modOff, modLength);
    }
    Cipher rsaCipher = Cipher.getInstance(cipherAlg, false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key, Cipher.MODE_DECRYPT);
    KMCipherImpl inst = new KMCipherImpl(rsaCipher);
    inst.setCipherAlgorithm(KMType.RSA);
    inst.setMode(KMType.DECRYPT);
    inst.setPaddingAlgorithm(padding);
    return inst;
  }

  private MGF1ParameterSpec getMGF1ParamSpec(byte mgfDigest) {
    switch (mgfDigest) {
      case KMType.SHA1:
        return MGF1ParameterSpec.SHA1;
      case KMType.SHA2_256:
        return MGF1ParameterSpec.SHA256;
      case KMType.SHA2_224:
        return MGF1ParameterSpec.SHA224;
      case KMType.SHA2_384:
        return MGF1ParameterSpec.SHA384;
      case KMType.SHA2_512:
        return MGF1ParameterSpec.SHA512;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    return null;
  }

  private KMCipher createRsaOAEP256Cipher(byte mode, byte mgfDigest,
      byte[] secret, short secretStart, short secretLen,
      byte[] modBuffer, short modOff, short modLength) {
    // Convert byte arrays into keys
    byte[] exp = null;
    byte[] mod = new byte[modLength];
    if (secret != null) {
      exp = new byte[secretLen];
      Util.arrayCopyNonAtomic(secret, secretStart, exp, (short) 0, secretLen);
    } else {
      exp = new byte[]{0x01, 0x00, 0x01};
    }
    Util.arrayCopyNonAtomic(modBuffer, modOff, mod, (short) 0, modLength);
    String modString = toHexString(mod);
    String expString = toHexString(exp);
    BigInteger modInt = new BigInteger(modString, 16);
    BigInteger expInt = new BigInteger(expString, 16);
    javax.crypto.Cipher rsaCipher = null;
    try {
      KeyFactory kf = KeyFactory.getInstance("RSA");
      // Create cipher with oaep padding
      OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
            getMGF1ParamSpec(mgfDigest), PSource.PSpecified.DEFAULT);
      rsaCipher = javax.crypto.Cipher.getInstance("RSA/ECB/OAEPPadding", "SunJCE");
      if (mode == KMType.ENCRYPT) {
        RSAPublicKeySpec pubSpec = new RSAPublicKeySpec(modInt, expInt);
        java.security.interfaces.RSAPublicKey pubKey = (java.security.interfaces.RSAPublicKey) kf
            .generatePublic(pubSpec);
        rsaCipher.init(javax.crypto.Cipher.ENCRYPT_MODE, pubKey, oaepSpec);
      } else {
        RSAPrivateKeySpec privSpec = new RSAPrivateKeySpec(modInt, expInt);
        java.security.interfaces.RSAPrivateKey privKey = (java.security.interfaces.RSAPrivateKey) kf
            .generatePrivate(privSpec);
        rsaCipher.init(javax.crypto.Cipher.DECRYPT_MODE, privKey, oaepSpec);
      }
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (InvalidKeySpecException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    }
    KMCipherImpl ret = new KMCipherImpl(rsaCipher);
    ret.setCipherAlgorithm(KMType.RSA);
    ret.setPaddingAlgorithm(KMType.RSA_OAEP);
    ret.setMode(mode);
    return ret;
  }

  private String toHexString(byte[] num) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < num.length; i++) {
      sb.append(String.format("%02X", num[i]));
    }
    return sb.toString();
  }

  public Signature createRsaSigner(short digest, short padding, byte[] secret,
      short secretStart, short secretLength, byte[] modBuffer,
      short modOff, short modLength) {
    short alg = mapSignature256Alg(KMType.RSA, (byte) padding);
    if (padding == KMType.PADDING_NONE ||
        (padding == KMType.RSA_PKCS1_1_5_SIGN && digest == KMType.DIGEST_NONE)) {
      return createNoDigestSigner(padding, secret, secretStart, secretLength,
          modBuffer, modOff, modLength);
    }
    Signature rsaSigner = Signature.getInstance((byte) alg, false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaSigner.init(key, Signature.MODE_SIGN);
    return rsaSigner;
  }

  private Signature createNoDigestSigner(short padding,
      byte[] secret, short secretStart, short secretLength,
      byte[] modBuffer, short modOff, short modLength) {
    Cipher rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,
        KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret, secretStart, secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key, Cipher.MODE_DECRYPT);
    KMRsa2048NoDigestSignature inst = new KMRsa2048NoDigestSignature(rsaCipher, (byte) padding,
        modBuffer, modOff, modLength);
    return inst;
  }

  public KeyAgreement createKeyAgreement(byte[] secret, short secretStart,
      short secretLength) {
    ECPrivateKey key = (ECPrivateKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setS(secret, secretStart, secretLength);

    KeyAgreement keyAgreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN,
        false);
    keyAgreement.init(key);
    return keyAgreement;
  }

  public Signature createEcSigner(short digest, byte[] secret, short secretStart,
      short secretLength) {
    short alg = mapSignature256Alg(KMType.EC, (byte) 0);
    Signature ecSigner;
    if (digest == KMType.DIGEST_NONE) {
      ecSigner = new KMEcdsa256NoDigestSignature(Signature.MODE_SIGN, secret, secretStart,
          secretLength);
    } else {
      ECPrivateKey key = (ECPrivateKey) KeyBuilder
          .buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
      key.setS(secret, secretStart, secretLength);
      ecSigner = Signature.getInstance((byte) alg, false);
      ecSigner.init(key, Signature.MODE_SIGN);
    }
    return ecSigner;
  }

  public KMCipher createSymmetricCipher(short alg, short purpose, short blockMode, short padding,
      byte[] secret,
      short secretStart, short secretLength,
      byte[] ivBuffer, short ivStart, short ivLength) {
    Key key = null;
    Cipher symmCipher = null;
    short len = 0;
    switch (secretLength) {
      case 32:
        len = KeyBuilder.LENGTH_AES_256;
        break;
      case 16:
        len = KeyBuilder.LENGTH_AES_128;
        break;
      case 24:
        len = KeyBuilder.LENGTH_DES3_3KEY;
        break;
      default:
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        break;
    }
    short cipherAlg = mapCipherAlg((byte) alg, (byte) padding, (byte) blockMode);
    switch (cipherAlg) {
      case Cipher.ALG_AES_BLOCK_128_CBC_NOPAD:
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, len, false);
        ((AESKey) key).setKey(secret, secretStart);
        symmCipher = Cipher.getInstance((byte) cipherAlg, false);
        symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, ivLength);
        break;
      case Cipher.ALG_AES_BLOCK_128_ECB_NOPAD:
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_AES, len, false);
        ((AESKey) key).setKey(secret, secretStart);
        symmCipher = Cipher.getInstance((byte) cipherAlg, false);
        symmCipher.init(key, mapPurpose(purpose));
        break;
      case Cipher.ALG_DES_CBC_NOPAD:
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, len, false);
        ((DESKey) key).setKey(secret, secretStart);
        symmCipher = Cipher.getInstance((byte) cipherAlg, false);
        //While sending back the iv send only 8 bytes.
        symmCipher.init(key, mapPurpose(purpose), ivBuffer, ivStart, (short) 8);
        break;
      case Cipher.ALG_DES_ECB_NOPAD:
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, len, false);
        ((DESKey) key).setKey(secret, secretStart);
        symmCipher = Cipher.getInstance((byte) cipherAlg, false);
        symmCipher.init(key, mapPurpose(purpose));
        break;
      case Cipher.ALG_AES_CTR: // uses SUNJCE
        return createAesCtrCipherNoPad(purpose, secret, secretStart, secretLength, ivBuffer,
            ivStart, ivLength);
      default://This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }
    KMCipherImpl cipher = new KMCipherImpl(symmCipher);
    cipher.setCipherAlgorithm(alg);
    cipher.setPaddingAlgorithm(padding);
    cipher.setMode(purpose);
    cipher.setBlockMode(blockMode);
    return cipher;
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

  private byte mapSignature256Alg(byte alg, byte padding) {
    switch (alg) {
      case KMType.RSA:
        switch (padding) {
          case KMType.RSA_PKCS1_1_5_SIGN:
            return Signature.ALG_RSA_SHA_256_PKCS1;
          case KMType.RSA_PSS:
            return Signature.ALG_RSA_SHA_256_PKCS1_PSS;
        }
        break;
      case KMType.EC:
        return Signature.ALG_ECDSA_SHA_256;
      case KMType.HMAC:
        return Signature.ALG_HMAC_SHA_256;
    }
    return -1;
  }

  private byte mapCipherAlg(byte alg, byte padding, byte blockmode) {
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
          case KMType.RSA_OAEP:
            return Cipher.ALG_RSA_PKCS1_OAEP;
        }
        break;
    }
    return -1;
  }

  private KMCipher createAesCtrCipherNoPad(short mode, byte[] secret, short secretStart,
      short secretLength, byte[] ivBuffer, short ivStart, short ivLength) {
    if (secretLength != 16 && secretLength != 32) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (ivLength != 16) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (mode != KMType.ENCRYPT && mode != KMType.DECRYPT) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    //Create the sun jce compliant aes key
    byte[] keyMaterial = new byte[secretLength];
    Util.arrayCopyNonAtomic(secret, secretStart, keyMaterial, (short) 0, secretLength);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial, (short) 0, keyMaterial.length, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    byte[] iv = new byte[ivLength];
    Util.arrayCopyNonAtomic(ivBuffer, ivStart, iv, (short) 0, ivLength);
    // Init Cipher
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    try {
      if (mode == KMType.ENCRYPT) {
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, aesKey, ivSpec);
      } else {
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, aesKey, ivSpec);
      }
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    KMCipherImpl ret = new KMCipherImpl(cipher);
    ret.setCipherAlgorithm(KMType.AES);
    ret.setMode(mode);
    ret.setPaddingAlgorithm((short) 0);
    ret.setBlockMode(KMType.CTR);
    return ret;
  }


  public Signature createHmacSignerVerifier(short purpose, short digest, byte[] secret,
      short secretStart, short secretLength) {
    short alg = Signature.ALG_HMAC_SHA_256;
    if (digest != KMType.SHA2_256) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    Signature hmacSignerVerifier = Signature.getInstance((byte) alg, false);
    HMACKey key = (HMACKey) KeyBuilder
        .buildKey(KeyBuilder.TYPE_HMAC, (short) (secretLength * 8), false);
    key.setKey(secret, secretStart, secretLength);
    hmacSignerVerifier.init(key, (byte) purpose);
    return hmacSignerVerifier;
  }

  private Signature createHmacSignerVerifier(short purpose, short digest, HMACKey key) {
    byte alg = Signature.ALG_HMAC_SHA_256;
    if (digest != KMType.SHA2_256) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    Signature hmacSignerVerifier = Signature.getInstance((byte) alg, false);
    hmacSignerVerifier.init(key, (byte) purpose);
    return hmacSignerVerifier;
  }

@Override
  public KMOperation getRkpOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode,
			KMDeviceUniqueKeyPair keyPair, byte[] ivBuf, short ivStart, short ivLength, short macLength) {
    KMOperation opr = null;
    switch (alg) {
    case KMType.EC:
      // get EC private key buffer
      byte[] tmpArray = new byte[100];
      ECPrivateKey ecPrivKey = (ECPrivateKey)((KMECDeviceUniqueKey)keyPair).ecKeyPair.getPrivate();
      short ecPrivKeyLen = ecPrivKey.getS(tmpArray, (short)0);
      Signature signer = createEcSigner(digest, tmpArray, (short)0, ecPrivKeyLen);
      opr = new KMOperationImpl(signer);
      break;
    
    default:
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
      break;
    }
    return opr;
  }

  public KMCipher createAesGcmCipher(short mode, short tagLen, byte[] secret, short secretStart,
      short secretLength,
      byte[] ivBuffer, short ivStart, short ivLength) {
    if (secretLength != 16 && secretLength != 32) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (ivLength != AES_GCM_NONCE_LENGTH) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (mode != KMType.ENCRYPT && mode != KMType.DECRYPT) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    //Create the sun jce compliant aes key
    byte[] keyMaterial = new byte[secretLength];
    Util.arrayCopyNonAtomic(secret, secretStart, keyMaterial, (short) 0, secretLength);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial, (short) 0, keyMaterial.length, "AES");
    // Create the cipher
    javax.crypto.Cipher cipher = null;
    try {
      cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
    } catch (NoSuchAlgorithmException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    } catch (NoSuchProviderException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (NoSuchPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    // Copy nonce
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(ivBuffer, ivStart, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(tagLen, iv, (short) 0, AES_GCM_NONCE_LENGTH);
    try {
      if (mode == KMType.ENCRYPT) {
        mode = javax.crypto.Cipher.ENCRYPT_MODE;
      } else {
        mode = javax.crypto.Cipher.DECRYPT_MODE;
      }
      cipher.init(mode, aesKey, spec);
    } catch (InvalidKeyException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.INVALID_INIT);
    } catch (InvalidAlgorithmParameterException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
    }
    KMCipherImpl ret = new KMCipherImpl(cipher);
    ret.setCipherAlgorithm(KMType.AES);
    ret.setMode(mode);
    ret.setPaddingAlgorithm((short) 0);
    ret.setBlockMode(KMType.GCM);
    return ret;
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
        // simulator does not support TRNG algorithm. So, PRNG algorithm (deprecated) is used.
        trng = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        trng.nextBytes(pool, (short) 0, (short) pool.length);
      } else {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
      }
    }
  }

  // Generate a secure random number from existing entropy pool. This uses aes ecb algorithm with
  // 8 byte rngCounter and 16 byte block size.
  @Override
  public void newRandomNumber(byte[] num, short startOff, short length) {
    byte[] countBuf = new byte[AES_BLOCK_SIZE];
    byte[] randBuf = new byte[AES_BLOCK_SIZE];
    short len = AES_BLOCK_SIZE;
    aesRngKey.setKey(entropyPool, (short) 0);
    aesRngCipher.init(aesRngKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0, (short) 16);
    while (length > 0) {
      if (length < len) {
        len = length;
      }
      // increment rngCounter by one
      incrementCounter();
      // copy the 8 byte rngCounter into the 16 byte rngCounter buffer.
      Util.arrayCopy(rngCounter, (short) 0, countBuf, (short) 0, (short) rngCounter.length);
      // encrypt the rngCounter buffer with existing entropy which forms the aes key.
      aesRngCipher.doFinal(
          countBuf, (short) 0, AES_BLOCK_SIZE, randBuf, (short) 0);
      // copy the encrypted rngCounter block to buffer passed in the argument
      Util.arrayCopy(randBuf, (short) 0, num, startOff, len);
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
        if (rngCounter[index] < 0) {
          break; // then break
        } else {
          index--; // else go to the higher order byte
        }
      } else {
        // if msb is not set then increment the rngCounter
        rngCounter[index]++;
        break;
      }
    }
  }

  @Override
  public void addRngEntropy(byte[] num, short offset, short length) {
    // Maximum length can be 256 bytes. But currently we support max 32 bytes seed.
    // Get existing entropy pool.
    if (length > 32) {
      length = 32;
    }
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
  public short getAttestationKeyAlgorithm(){
    return KMType.INVALID_VALUE;
  }

  @Override
  public KMDeviceUniqueKeyPair createRkpDeviceUniqueKeyPair(
      KMDeviceUniqueKeyPair key, byte[] pubKey, short pubKeyOff,
      short pubKeyLen, byte[] privKey, short privKeyOff, short privKeyLen) {
    if (key == null) {
      KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      key = new KMECDeviceUniqueKey(ecKeyPair);
    }
    ECPrivateKey ecKeyPair = (ECPrivateKey) ((KMECDeviceUniqueKey) key).ecKeyPair.getPrivate();
    ECPublicKey ecPublicKey = (ECPublicKey) ((KMECDeviceUniqueKey) key).ecKeyPair.getPublic();
    ecKeyPair.setS(privKey, privKeyOff, privKeyLen);
    ecPublicKey.setW(pubKey, pubKeyOff, pubKeyLen);
    return (KMDeviceUniqueKeyPair) key;
  }

  @Override
  public short rsaSign256Pkcs1(
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
      short outputDataStart){
    Signature signer = createRsaSigner(KMType.SHA2_256, KMType.RSA_PKCS1_1_5_SIGN,secret,secretStart,secretLength,modBuf,modStart,modLength);
    return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
  }

  @Override
  public short ecSign256(byte[] secret, short secretStart, short secretLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart){
    Signature signer = createEcSigner(KMType.SHA2_256, secret, secretStart, secretLength);
    return signer.sign(inputDataBuf, inputDataStart, inputDataLength, outputDataBuf, outputDataStart);
  }

  @Override
  public short ecSign256(KMAttestationKey attestationKey,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {

    ECPrivateKey key = (ECPrivateKey)((KMECPrivateKey) attestationKey).ecKeyPair.getPrivate();

    Signature signer = Signature
        .getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(key, Signature.MODE_SIGN);
    return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
  }


  @Override
  public short ecSign256(KMDeviceUniqueKeyPair deviceUniqueKey, byte[] inputDataBuf, short inputDataStart,
                         short inputDataLength, byte[] outputDataBuf, short outputDataStart) {
    ECPrivateKey key = (ECPrivateKey)((KMECDeviceUniqueKey) deviceUniqueKey).ecKeyPair.getPrivate();
    Signature signer = Signature
        .getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(key, Signature.MODE_SIGN);
    return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
  }

  @Override
  public boolean ecVerify256(byte[] pubKey, short pubKeyOffset, short pubKeyLen, byte[] inputDataBuf,
                             short inputDataStart, short inputDataLength, byte[] signatureDataBuf,
                             short signatureDataStart, short signatureDataLen) {

    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    ecPublicKey.setW(pubKey, pubKeyOffset, pubKeyLen);

    Signature signer = Signature
        .getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(ecPublicKey, Signature.MODE_VERIFY);
    return signer.verify(inputDataBuf, inputDataStart, inputDataLength,
        signatureDataBuf, signatureDataStart, signatureDataLen);
  }

  @Override
  public boolean isUpgrading() {
    return false;
  }

  @Override
  public KMComputedHmacKey createComputedHmacKey(
      KMComputedHmacKey computedHmacKey, byte[] keyData,
      short offset, short length) {
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (computedHmacKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (length * 8),
          false);
      computedHmacKey = new KMHmacKey(key);
    }
   ((KMHmacKey) computedHmacKey).hmacKey.setKey(keyData, offset, length);
    return (KMComputedHmacKey) computedHmacKey;
  }

  @Override
  public com.android.javacard.seprovider.KMMasterKey createMasterKey(
      com.android.javacard.seprovider.KMMasterKey masterKey, short keySizeBits) {
    if (masterKey == null) {
      AESKey key = (AESKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_AES, keySizeBits, false);
      masterKey = new KMAESKey(key);
      short keyLen = (short) (keySizeBits / 8);
      byte[] keyData = new byte[keyLen];
      getTrueRandomNumber(keyData, (short) 0, keyLen);
      ((KMAESKey)masterKey).aesKey.setKey(keyData, (short) 0);
    }
    return (KMMasterKey) masterKey;
  }

  @Override
  public boolean isAttestationKeyProvisioned(){
    return false;
  }

  public boolean isPowerReset(){
    boolean flag = false;
    if(resetFlag[0] == POWER_RESET_TRUE){
      resetFlag[0] = POWER_RESET_FALSE;
      flag = true;
    }
    return flag;
  }

  @Override
  public short messageDigest256(byte[] inBuff, short inOffset,
      short inLength, byte[] outBuff, short outOffset) {
    MessageDigest mDigest = null;
    short len = 0;
    try {
      mDigest = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
      len = mDigest.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    } catch (Exception e) {

    }
    return len;
  }

  @Override
  public void onSave(Element element, byte interfaceType, Object object) {

  }

  @Override
  public Object onRestore(Element element) {
    return null;
  }

  @Override
  public short getBackupPrimitiveByteCount(byte interfaceType) {
    return 0;
  }

  @Override
  public short getBackupObjectCount(byte interfaceType) {
    return 0;
  }

  @Override
  public KMRkpMacKey createRkpMacKey(KMRkpMacKey rkpMacKey, byte[] keyData,
      short offset, short length) {
    if (rkpMacKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) (length * 8),
          false);
      rkpMacKey = new KMHmacKey(key);
    }
    ((KMHmacKey) rkpMacKey).hmacKey.setKey(keyData, offset, length);
    return rkpMacKey;
  }

  @Override
  public com.android.javacard.seprovider.KMPreSharedKey createPreSharedKey(
      com.android.javacard.seprovider.KMPreSharedKey presharedKey, byte[] keyData, short offset,
      short length) {
    short lengthInBits = (short) (length * 8);
    if ((lengthInBits % 8 != 0) || !(lengthInBits >= 64 && lengthInBits <= 512)) {
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    if (preSharedKey == null) {
      HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, lengthInBits,
          false);
      preSharedKey = new KMHmacKey(key);
    }
    ((KMHmacKey)preSharedKey).hmacKey.setKey(keyData, offset, length);
    return (KMPreSharedKey) preSharedKey;
  }

  @Override
  public boolean isBootSignalEventSupported() {
    return isBootEventSignalSupported;
  }

  @Override
  public boolean isDeviceRebooted() {
    return isDeviceRebooted;
  }

  @Override
  public void clearDeviceBooted(boolean resetBootFlag) {
    isDeviceRebooted = false;
  }
}
