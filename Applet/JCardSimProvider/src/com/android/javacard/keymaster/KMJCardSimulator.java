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

import javacard.framework.APDU;
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
import javacard.security.RSAPublicKey;
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
  private static final short CERT_CHAIN_OFFSET = 0;
  private static final short CERT_ISSUER_OFFSET = KMConfigurations.CERT_CHAIN_MAX_SIZE;
  private static final short CERT_EXPIRY_OFFSET =
      (short) (CERT_ISSUER_OFFSET + KMConfigurations.CERT_ISSUER_MAX_SIZE);
  private static final short COMPUTED_HMAC_KEY_SIZE = 32;

  public static boolean jcardSim = false;
  private static Signature kdf;
  private static Signature hmacSignature;

  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;
  private byte[] provisionData;
  private KMAESKey masterKey;
  private KMECPrivateKey attestationKey;
  private KMHmacKey preSharedKey;
  private KMHmacKey computedHmacKey;
  private byte[] oemRootPublicKey;

  private static KMJCardSimulator jCardSimulator = null;

  public static KMJCardSimulator getInstance() {
    return jCardSimulator;
  }

  // Implements Oracle Simulator based restricted crypto provider
  public KMJCardSimulator() {
    // Various Keys
    kdf = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
    hmacSignature = Signature.getInstance(Signature.ALG_HMAC_SHA_256, false);
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
    //Allocate buffer for certificate chain and cert parameters.
    // First 2 bytes is reserved for length for all the 3 buffers.
    short totalLen = (short) (6 +  KMConfigurations.CERT_CHAIN_MAX_SIZE +
        KMConfigurations.CERT_ISSUER_MAX_SIZE + KMConfigurations.CERT_EXPIRY_MAX_SIZE);
    provisionData = new byte[totalLen];
    oemRootPublicKey = new byte[65];
    jCardSimulator = this;
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
    // Create auth data
    byte[] aad = new byte[authDataLen];
    Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0, authDataLen);
    cipher.updateAAD(aad);
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
    // Create auth data
    byte[] aad = new byte[authDataLen];
    Util.arrayCopyNonAtomic(authData, authDataStart, aad, (short) 0,
        authDataLen);
    cipher.updateAAD(aad);
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
    Util.arrayCopy(entropyPool, (short) 0, buf, start, length);
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
    short keyMaterialLen = key.getKeySizeBits();
    keyMaterialLen = (short) (keyMaterialLen / 8);
    short keyMaterialStart = 0;
    byte[] keyMaterial = new byte[keyMaterialLen];
    key.getKey(keyMaterial, keyMaterialStart);
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
    short keyLen = (short) (aesKey.getKeySizeBits() / 8);
    byte[] keyData = new byte[keyLen];
    aesKey.getKey(keyData, (short) 0);
    return hmacSign(keyData, (short) 0, keyLen, data, dataStart, dataLength,
        signature, signatureStart);
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
  public short hmacSign(byte[] keyBuf, short keyStart, short keyLength, byte[] data,
      short dataStart, short dataLength, byte[] mac, short macStart) {
    HMACKey key = createHMACKey(keyBuf, keyStart, keyLength);
    return hmacSign(key, data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public short rsaDecipherOAEP256(byte[] secret, short secretStart, short secretLength,
      byte[] modBuffer, short modOff, short modLength,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {
    KMCipher cipher = createRsaDecipher(
        KMType.RSA_OAEP, KMType.SHA2_256, secret, secretStart, secretLength, modBuffer, modOff,
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
  public KMOperation initTrustedConfirmationSymmetricOperation(KMComputedHmacKey computedHmacKey) {
    KMOperationImpl opr = null;
    KMHmacKey key = (KMHmacKey) computedHmacKey;
    Signature signerVerifier = createHmacSignerVerifier(KMType.VERIFY, KMType.SHA2_256, key.getKey());
    return new KMOperationImpl(signerVerifier);
  }
  
  @Override
  public KMOperation initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest,
      byte[] privKeyBuf, short privKeyStart, short privKeyLength,
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
                  padding, digest, privKeyBuf, privKeyStart, privKeyLength, pubModBuf, pubModStart,
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

  private KMCipher createRsaOAEP256Cipher(byte mode, byte digest,
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
      OAEPParameterSpec oaepSpec = null;
      if (digest == KMType.SHA2_256) {
        oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      } else {
        oaepSpec = new OAEPParameterSpec("SHA1", "MGF1",
            MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
      }
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


  public KMCipher createSymmetricCipher(
      short cipherAlg, short mode, short blockMode, short padding, byte[] secret, short secretStart,
      short secretLength) {
    return createSymmetricCipher(cipherAlg, mode, blockMode, padding, secret, secretStart,
        secretLength, null, (short) 0, (short) 0);
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

  private Signature createHmacSignerVerifier(short purpose, short digest,
      byte[] secret, short secretStart, short secretLength) {
    HMACKey key = createHMACKey(secret, secretStart, secretLength);
    return createHmacSignerVerifier(purpose, digest, key);
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
    KMRepository repository = KMRepository.instance();
    byte[] bufPtr = repository.getHeap();
    short countBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short randBufInd = repository.alloc(KMKeymasterApplet.AES_BLOCK_SIZE);
    short len = KMKeymasterApplet.AES_BLOCK_SIZE;
    aesRngKey.setKey(entropyPool, (short) 0);
    aesRngCipher.init(aesRngKey, Cipher.MODE_ENCRYPT, aesICV, (short) 0, (short) 16);
    while (length > 0) {
      if (length < len) {
        len = length;
      }
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
  public KMAttestationCert getAttestationCert(boolean rsaCert) {
    return KMAttestationCertImpl.instance(rsaCert);
  }

  @Override
  public KMPKCS8Decoder getPKCS8DecoderInstance() {
    return KMPKCS8DecoderImpl.instance();
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
    JCSystem.beginTransaction();
    Util.setShort(provisionData, copyToOff, len);
    Util.arrayCopyNonAtomic(buf, off, provisionData, (short) (copyToOff + 2), len);
    JCSystem.commitTransaction();
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
    JCSystem.beginTransaction();
    Util.arrayFillNonAtomic(provisionData, (short) 0, (short) provisionData.length, (byte) 0);
    JCSystem.commitTransaction();
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
  public short ecSign256(KMAttestationKey attestationKey,
      byte[] inputDataBuf, short inputDataStart, short inputDataLength,
      byte[] outputDataBuf, short outputDataStart) {

    ECPrivateKey key = ((KMECPrivateKey) attestationKey).getPrivateKey();

    Signature signer = Signature
        .getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(key, Signature.MODE_SIGN);
    return signer.sign(inputDataBuf, inputDataStart, inputDataLength,
        outputDataBuf, outputDataStart);
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
  }

  @Override
  public void onSave(Element ele) {
  }

  @Override
  public void onRestore(Element ele, short oldVersion, short currentVersion) {
  }

  @Override
  public short getBackupPrimitiveByteCount() {
    return 0;
  }

  @Override
  public short getBackupObjectCount() {
    return 0;
  }

  @Override
  public boolean isUpgrading() {
    return false;
  }

  @Override
  public KMMasterKey createMasterKey(short keySizeBits) {
    if (masterKey == null) {
      AESKey key = (AESKey) KeyBuilder.buildKey(
          KeyBuilder.TYPE_AES, keySizeBits, false);
      masterKey = new KMAESKey(key);
      short keyLen = (short) (keySizeBits / 8);
      byte[] keyData = new byte[keyLen];
      getTrueRandomNumber(keyData, (short) 0, keyLen);
      masterKey.setKey(keyData, (short) 0);
    }
    return (KMMasterKey) masterKey;
  }

  @Override
  public KMAttestationKey createAttestationKey(byte[] keyData, short offset,
      short length) {
    if (attestationKey == null) {
      // Strongbox supports only P-256 curve for EC key.
      KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
      attestationKey = new KMECPrivateKey(ecKeyPair);
    }
    attestationKey.setS(keyData, offset, length);
    return (KMAttestationKey) attestationKey;
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
  public KMComputedHmacKey getComputedHmacKey() {
    KMHmacKey key = (KMHmacKey) computedHmacKey;
    byte length = key.getKey(tmpArray, (short) 0);
    if (length != COMPUTED_HMAC_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    Util.arrayFillNonAtomic(tmpArray, (short) 32, (short) 32, (byte) 0);
    if (0 == Util.arrayCompare(tmpArray, (short) 0, tmpArray, (short) 32, COMPUTED_HMAC_KEY_SIZE)) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return computedHmacKey;
  }

  @Override
  public void releaseAllOperations() {
    //Do nothing.
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
  public boolean ecVerify256(byte[] keyBuf, short keyBufStart, short keyBufLen, byte[] inputDataBuf,
      short inputDataStart, short inputDataLength, byte[] signatureDataBuf,
      short signatureDataStart, short signatureDataLen) {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPublicKey ecPublicKey = (ECPublicKey) ecKeyPair.getPublic();
    ecPublicKey.setW(keyBuf, keyBufStart, keyBufLen);
    Signature signer = Signature
        .getInstance(Signature.ALG_ECDSA_SHA_256, false);
    signer.init(ecPublicKey, Signature.MODE_VERIFY);
    return signer.verify(inputDataBuf, inputDataStart, inputDataLength,
        signatureDataBuf, signatureDataStart, signatureDataLen);
  }

  @Override
  public boolean isValidCLA(APDU apdu) {
    /**
     * Returns whether the current APDU command CLA byte is valid. The CLA byte is invalid
     * if the CLA bits (b8,b7,b6) is %b001, which is a CLA encoding reserved for future use(RFU),
     * or if CLA is 0xFF which is an invalid value as defined in the ISO 7816-4:2013 specification.
     */
    byte[] apduBuffer = apdu.getBuffer();
    short apduClass = (short) (apduBuffer[ISO7816.OFFSET_CLA] & 0x00FF);
    if (((apduClass & 0x00E0) == 0x0020) ||
        (apduClass == 0x00FF)) {
      return false;
    }
    return true;
  }

}
