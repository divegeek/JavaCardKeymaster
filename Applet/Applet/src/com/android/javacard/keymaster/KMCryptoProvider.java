package com.android.javacard.keymaster;

import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;

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

  ECPrivateKey createEcKey(byte[] privBuffer, short privOff, short privLength);

  HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength);

  DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength);

  RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength,
                                    byte[] privBuffer, short privOff, short privLength);

  HMACKey cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength);

  short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart);
  boolean hmacVerify(HMACKey key, byte[] data, short dataStart, short dataLength,
                            byte[] mac, short macStart, short macLength);

  KMCipher createRsaDecrypt(short cipherAlg, short padding,
                            byte[] secret, short secretStart, short secretLength,
                            byte[] modBuffer, short modOff, short modLength);
  Signature createRsaSigner(short msgDigestAlg, short padding, byte[] secret, short secretStart,
                           short secretLength,byte[] modBuffer, short modOff, short modLength);
  Signature createEcSigner(short msgDigestAlg, byte[] secret, short secretStart,
                           short secretLength);
  KMCipher createSymmetricCipher(short cipherAlg, short padding, short mode,
                               byte[] secret, short secretStart, short secretLength,
                               byte[] ivBuffer, short ivStart, short ivLength);
  Signature createHmacSigner(short msgDigestAlg,
                                  byte[] secret, short secretStart, short secretLength);
  KMCipher createGCMCipher(short mode, byte[] secret, short secretStart, short secretLength,
                         byte[] ivBuffer, short ivStart, short ivLength);
  void delete(KMCipher cipher);
  void delete(Signature signature);
  void delete(Key key);
  void delete(KeyPair keyPair);
  //TODO remove this later
  void bypassAesGcm();
}
