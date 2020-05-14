package com.android.javacard.keymaster;

import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;

public interface KMCryptoProvider {
  KeyPair createRsaKeyPair();

  KeyPair createECKeyPair();

  AESKey createAESKey(short keysize);

  AESKey createAESKey(byte[] buf, short startOff, short length);

  DESKey createTDESKey();

  HMACKey createHMACKey(short keysize);

  void newRandomNumber(byte[] num, short offset, short length);

  void addRngEntropy(byte[] num, short offset, short length);

  short aesGCMEncrypt(
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
      short authTagLen);

  boolean aesGCMDecrypt(
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
    short authTagLen);

  byte[] getTrueRandomNumber(short len);

  short aesCCMSign(
    byte[] bufIn,
    short bufInStart,
    short buffInLength,
    byte[] masterKeySecret,
    byte[] bufOut,
    short bufStart);

  ECPrivateKey createEcPrivateKey(byte[] pubBuffer, short pubOff, short pubLength,
                                             byte[] privBuffer, short privOff, short privLength);

  HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength);

  DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength);

  RSAPrivateKey createRsaPrivateKey(byte[] modBuffer, short modOff, short modLength,
                                    byte[] privBuffer, short privOff, short privLength);
}
