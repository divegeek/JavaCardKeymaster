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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Simulator only supports 512 bit RSA key pair, 128 AES Key, 128 bit 3Des key, less then 256 bit EC
 * Key, and upto 512 bit HMAC key. Also simulator does not support TRNG, so this implementation just
 * creates its own RNG using PRNG.
 */
public class KMJcardSimulator implements KMCryptoProvider {
  public static final short AES_GCM_TAG_LENGTH = 12;
  public static final short AES_GCM_NONCE_LENGTH = 12;
  public static final short MAX_RND_NUM_SIZE = 64;
  public static final short ENTROPY_POOL_SIZE = 16; // simulator does not support 256 bit aes keys
  public static final byte[] aesICV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  private static final int AES_GCM_KEY_SIZE = 16;
  public static boolean jcardSim = false;
  private static Signature kdf;
  private static Signature hmacSignature;

  private static byte[] rngCounter;
  private static AESKey aesRngKey;
  private static Cipher aesRngCipher;
  private static byte[] entropyPool;
  private static byte[] rndNum;

  // Implements Oracle Simulator based restricted crypto provider
  public KMJcardSimulator() {
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

  }

  @Override
  public KeyPair createRsaKeyPair() {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    rsaKeyPair.genKeyPair();
    return rsaKeyPair;
  }

  @Override
  public RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength,
                                    byte[] privBuffer, short privOff, short privLength) {
    KeyPair rsaKeyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
    RSAPrivateKey privKey = (RSAPrivateKey) rsaKeyPair.getPrivate();
    privKey.setExponent(privBuffer, privOff, privLength);
    privKey.setModulus(modBuffer, modOff, modLength);
    return privKey;

  }

  @Override
  public KeyPair createECKeyPair() {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ecKeyPair.genKeyPair();
    return ecKeyPair;
  }

  @Override
  public ECPrivateKey createEcKey(byte[] privBuffer, short privOff, short privLength) {
    KeyPair ecKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
    ECPrivateKey privKey = (ECPrivateKey) ecKeyPair.getPrivate();
    if(privLength > 24){
      privLength = 24;// simulator does not support more then 24 bytes - 192 bit key.
    }else if(privLength <= 20){
      return null;
    }
    privKey.setS(privBuffer,privOff, privLength);
    return privKey;
  }

  @Override
  public AESKey createAESKey(short keysize) {
    byte[] rndNum = new byte[(short) (keysize/8)];
    return createAESKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public AESKey createAESKey(byte[] buf, short startOff, short length) {
    AESKey key = null;
    short keysize = (short)(length * 8);
    if (keysize == 128) {
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
      key.setKey(buf, (short) startOff);
    }else if (keysize == 256){
      key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
      key.setKey(buf, (short) startOff);
    }
 //   byte[] buffer = new byte[length];
 //   Util.arrayCopyNonAtomic(buf, startOff, buffer, (short)0,length);
 //   print("AES Key", buffer);
    return key;
  }

  @Override
  public DESKey createTDESKey() {
    // TODO check whether 168 bit or 192 bit
    byte[] rndNum = new byte[24];
    newRandomNumber(rndNum, (short) 0, (short)rndNum.length);
    return createTDESKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength) {
    DESKey triDesKey =
      (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY, false);
    triDesKey.setKey(secretBuffer, secretOff);
    return triDesKey;
  }

  @Override
  public HMACKey createHMACKey(short keysize) {
    if((keysize % 8 != 0) || !(keysize >= 64 && keysize <= 512)){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] rndNum = new byte[(short) (keysize/8)];
    newRandomNumber(rndNum, (short) 0, (short)(keysize/8));
    return createHMACKey(rndNum, (short)0, (short)rndNum.length);
  }

  @Override
  public HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength) {
    HMACKey key = null;
    key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC,
      KeyBuilder.LENGTH_HMAC_SHA_256_BLOCK_64, false);
    key.setKey(secretBuffer,secretOff,secretLength);
    return key;
  }

  @Override
  public short aesGCMEncrypt(
      AESKey key,
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
    if(key.getSize() != 128){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] keyMaterial = new byte[16];
    key.getKey(keyMaterial,(short)0);
  //  print("KeyMaterial", keyMaterial);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial,(short)0,(short)16, "AES");
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
    if(nonceLen != AES_GCM_NONCE_LENGTH){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
    Util.arrayCopyNonAtomic(nonce,nonceStart,iv,(short)0,AES_GCM_NONCE_LENGTH);
    // Init Cipher
    GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce,nonceStart,AES_GCM_NONCE_LENGTH);
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
    Util.arrayCopyNonAtomic(authData,authDataStart,aad,(short)0,authDataLen);
   // print("AAD", aad);
    cipher.updateAAD(aad);
    // Encrypt secret
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize(secretLen)];
    try {
      len =  (short)(cipher.doFinal(secret,secretStart,secretLen,outputBuf,(short)0));
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
    Util.arrayCopyNonAtomic(outputBuf, (short)(len - AES_GCM_TAG_LENGTH),authTag,authTagStart,AES_GCM_TAG_LENGTH);
    //Copy the encrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short)0,encSecret,encSecretStart,(short)(len - AES_GCM_TAG_LENGTH));
    return (short)(len - AES_GCM_TAG_LENGTH);
  }

/*
    // Decrypt; nonce is shared implicitly
    cipher.init(Cipher.DECRYPT_MODE, key, spec);

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because AAD value is altered
    if (testNum == 1) aad[1]++;

    cipher.updateAAD(aad);

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because the encrypted data has been altered
    if (testNum == 2) cipherText[10]++;

    // EXPECTED: Uncommenting this will cause an AEADBadTagException when decrypting
    // because the tag has been altered
    if (testNum == 3) cipherText[cipherText.length - 2]++;

    try {
      byte[] plainText = cipher.doFinal(cipherText);
      if (testNum != 0) {
        System.out.println("Test Failed: expected AEADBadTagException not thrown");
      } else {
        // check if the decryption result matches
        if (Arrays.equals(input, plainText)) {
          System.out.println("Test Passed: match!");
        } else {
          System.out.println("Test Failed: result mismatch!");
          System.out.println(new String(plainText));
        }
      }
    } catch(AEADBadTagException ex) {
      if (testNum == 0) {
        System.out.println("Test Failed: unexpected ex " + ex);
        ex.printStackTrace();
      } else {
        System.out.println("Test Passed: expected ex " + ex);
      }
    }
  }
  }*/

  public boolean aesGCMDecrypt(
      AESKey key,
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
  //Create the sun jce compliant aes key
    if(key.getSize() != 128){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    byte[] keyMaterial = new byte[16];
    key.getKey(keyMaterial,(short)0);
    java.security.Key aesKey = new SecretKeySpec(keyMaterial,(short)0,(short)16, "AES");
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
  if(nonceLen != AES_GCM_NONCE_LENGTH){
  CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
  }
  byte[] iv = new byte[AES_GCM_NONCE_LENGTH];
  Util.arrayCopyNonAtomic(nonce,nonceStart,iv,(short)0,AES_GCM_NONCE_LENGTH);
  // Init Cipher
  GCMParameterSpec spec = new GCMParameterSpec(AES_GCM_TAG_LENGTH * 8, nonce,nonceStart,AES_GCM_NONCE_LENGTH);
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
  Util.arrayCopyNonAtomic(authData,authDataStart,aad,(short)0,authDataLen);
  cipher.updateAAD(aad);
  // Append the auth tag at the end of data
    byte[] inputBuf = new byte[(short)(encSecretLen + AES_GCM_TAG_LENGTH)];
    Util.arrayCopyNonAtomic(encSecret,encSecretStart,inputBuf,(short)0,encSecretLen);
    Util.arrayCopyNonAtomic(authTag,authTagStart,inputBuf,encSecretLen,AES_GCM_TAG_LENGTH);
  // Decrypt
    short len = 0;
    byte[] outputBuf = new byte[cipher.getOutputSize((short)inputBuf.length)];
    try {
      len =  (short)(cipher.doFinal(inputBuf,(short)0,(short)inputBuf.length,outputBuf,(short)0));
    }catch(AEADBadTagException e){
      e.printStackTrace();
      return false;
    }catch (ShortBufferException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (IllegalBlockSizeException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    } catch (BadPaddingException e) {
      e.printStackTrace();
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    //Copy the decrypted data
    Util.arrayCopyNonAtomic(outputBuf, (short)0,secret,secretStart,len);
    return true;
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

    AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
    key.setKey(masterKeySecret, (short) 0);
    byte[] in = new byte[buffInLength];
    Util.arrayCopyNonAtomic(bufIn, bufInStart,in,(short)0,buffInLength);
    kdf.init(key, Signature.MODE_SIGN);
    short len = kdf.sign(bufIn, bufInStart, buffInLength, bufOut, bufStart);
    byte[] out = new byte[len];
    Util.arrayCopyNonAtomic(bufOut, bufStart,out,(short)0,len);
    return len;
  }


  @Override
  public HMACKey cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength) {
    return null;
  }

  @Override
  public short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart) {
    hmacSignature.init(key, Signature.MODE_SIGN);
    return hmacSignature.sign(data, dataStart, dataLength, mac, macStart);
  }

  @Override
  public boolean hmacVerify(HMACKey key, byte[] data, short dataStart, short dataLength,
                          byte[] mac, short macStart, short macLength) {
    hmacSignature.init(key, Signature.MODE_VERIFY);
    return hmacSignature.verify(data, dataStart, dataLength, mac, macStart, macLength);
  }

  @Override
  public KMCipher createRsaDecrypt(short cipherAlg, short padding, byte[] secret, short secretStart,
                                   short secretLength, byte[] modBuffer, short modOff, short modLength) {
    Cipher rsaCipher = Cipher.getInstance((byte)cipherAlg,
      (byte)padding,false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret,secretStart,secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaCipher.init(key,Cipher.MODE_DECRYPT);
    return new KMCipherImpl(rsaCipher);
  }

  @Override
  public Signature createRsaSigner(short msgDigestAlg, short padding, byte[] secret, short secretStart, short secretLength, byte[] modBuffer, short modOff, short modLength) {
    Signature rsaSigner = Signature.getInstance((byte)msgDigestAlg, Signature.SIG_CIPHER_RSA,(byte)padding,false);
    RSAPrivateKey key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_2048, false);
    key.setExponent(secret,secretStart,secretLength);
    key.setModulus(modBuffer, modOff, modLength);
    rsaSigner.init(key,Signature.MODE_SIGN);
    return rsaSigner;
  }

  @Override
  public Signature createEcSigner(short msgDigestAlg, byte[] secret, short secretStart, short secretLength) {
    Signature ecSigner = Signature.getInstance((byte)msgDigestAlg, Signature.SIG_CIPHER_ECDSA,Cipher.PAD_NOPAD,false);
    ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
    key.setS(secret,secretStart,secretLength);
    ecSigner.init(key,Signature.MODE_SIGN);
    return ecSigner;
  }

  @Override
  public KMCipher createSymmetricCipher(short cipherAlg, short padding, short mode, byte[] secret,
                                        short secretStart, short secretLength,
                                        byte[] ivBuffer, short ivStart, short ivLength) {
    Key key = null;
    short len = 0;
    if(cipherAlg == Cipher.CIPHER_AES_CBC || cipherAlg == Cipher.CIPHER_AES_CBC){
      if(secretLength == 32){
        len = KeyBuilder.LENGTH_AES_256;
      }else if(secretLength == 16){
        len = KeyBuilder.LENGTH_AES_128;
      }else{
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }

      //TODO
    }else if(secretLength != 21){ // DES Key
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }else{ //DES Key
      len = KeyBuilder.LENGTH_DES3_3KEY;
    }
    switch(cipherAlg){
      case Cipher.CIPHER_AES_CBC:
      case Cipher.CIPHER_AES_ECB:
        key = KeyBuilder.buildKey(KeyBuilder.TYPE_AES,len,false);
        ((AESKey) key).setKey(secret,secretStart);
        break;
      case Cipher.CIPHER_DES_CBC:
      case Cipher.CIPHER_DES_ECB:
        key = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,len,false);
        ((DESKey) key).setKey(secret,secretStart);
        break;
      default://This should never happen
        CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        break;
    }

    //TODO
    Cipher symmCipher = Cipher.getInstance((byte)cipherAlg, Cipher.PAD_NOPAD,false);
    if (ivBuffer != null) {
      symmCipher.init(key, (byte) mode, ivBuffer, ivStart, ivLength);
    }else{
      symmCipher.init(key, (byte) mode);
    }
    return new KMCipherImpl(symmCipher);
  }

  @Override
  public Signature createHmacSigner(short msgDigestAlg, byte[] secret, short secretStart, short secretLength) {
    Signature hmacSigner = Signature.getInstance((byte)msgDigestAlg, Signature.SIG_CIPHER_HMAC,Cipher.PAD_NOPAD,false);
    HMACKey key = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short)(secretLength*8), false);
    key.setKey(secret,secretStart,secretLength);
    hmacSigner.init(key,Signature.MODE_SIGN);
    return hmacSigner;
  }

  @Override
  public KMCipher createGCMCipher(short mode, byte[] secret, short secretStart, short secretLength, byte[] ivBuffer, short ivStart, short ivLength) {
    //TODO
    short len = KeyBuilder.LENGTH_AES_128;
    if(secretLength == 32){
      len = KeyBuilder.LENGTH_AES_256;
    }
    return new KMCipherImpl(null);
  }

  @Override
  public void delete(KMCipher cipher) {
    //Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(Signature signature) {
    //Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(Key key) {
    // Don't do anything as we don't pool the objects.
  }

  @Override
  public void delete(KeyPair keyPair) {
    // Don't do anything as we don't pool the objects.
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
  private void print (String lab, byte[] b, short s, short l){
    byte[] i = new byte[l];
    Util.arrayCopyNonAtomic(b,s,i,(short)0,l);
    print(lab,i);
  }
  private void print(String label, byte[] buf){
    System.out.println(label+": ");
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < buf.length; i++){
      sb.append(String.format(" 0x%02X", buf[i])) ;
      if(((i-1)%38 == 0) && ((i-1) >0)){
        sb.append(";\n");
      }
    }
    System.out.println(sb.toString());
  }
  @Override
  public void bypassAesGcm(){
    //ignore
  }
}
