package com.android.javacard.keymaster;

import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPrivateKey;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.Signature;

public interface KMSEProvider {
  KeyPair createRsaKeyPair();
  KeyPair createECKeyPair();
  ECPrivateKey createEcKey(byte[] privBuffer, short privOff, short privLength);
  RSAPrivateKey createRsaKey(byte[] modBuffer, short modOff, short modLength,
                             byte[] privBuffer, short privOff, short privLength);

  HMACKey createHMACKey(byte[] secretBuffer, short secretOff, short secretLength);
  DESKey createTDESKey(byte[] secretBuffer, short secretOff, short secretLength);
  AESKey createAESKey(short keysize);
  AESKey createAESKey(byte[] buf, short startOff, short length);
  DESKey createTDESKey();
  HMACKey createHMACKey(short keysize);
  short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff);


  // Oneshot Operations
  void newRandomNumber(byte[] num, short offset, short length);
  void addRngEntropy(byte[] num, short offset, short length);
  byte[] getTrueRandomNumber(short len);

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

  short aesCCMSign(
    byte[] bufIn,
    short bufInStart,
    short buffInLength,
    byte[] masterKeySecret,
    byte[] bufOut,
    short bufStart);

  HMACKey cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength);

  short cmacKdf(byte[] keyMaterial, byte[] label, byte[] context, short contextStart, short contextLength, byte[] keyBuf, short keyStart);

  short hmacSign(HMACKey key, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart);
  boolean hmacVerify(HMACKey key, byte[] data, short dataStart, short dataLength,
                     byte[] mac, short macStart, short macLength);
  short hmacSign(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart);
  boolean hmacVerify(byte[] keyBuf, short keyStart, short keyLength, byte[] data, short dataStart, short dataLength,
                     byte[] mac, short macStart, short macLength);

  // Persistent Operations
  short initSymmetricOperation(byte purpose, byte alg, byte digest, byte padding, byte blockMode,
                               byte[] keyBuf, short keyStart, short keyLength);
  short initSymmetricOperation(byte purpose, byte alg, byte digest,
                               byte[] keyBuf, short keyStart, short keyLength);
  short initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest,
                               byte[] privKeyBuf, short privKeyStart, short privKeyLength,
                                byte[] modBuf, short modStart, short modLength);
  short initAsymmetricOperation(byte purpose, byte alg, byte padding, byte digest,
                                byte[] privKeyBuf, short privKeyStart, short privKeyLength);
  short updateOperation(short opHandle, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
                        byte[] outputDataBuf, short outputDataStart);
  short finishOperation(short opHandle, byte[] inputDataBuf, short inputDataStart, short inputDataLength,
                        byte[] outputDataBuf, short outputDataStart);
  void abortOperation(short opHandle);

  short hmacInit(byte[] keyBuf, short keyStart, short keyLength, byte digest, byte mode);
  short hmacSign(short opHandle, byte[] data, short dataStart, short dataLength, byte[] mac, short macStart);
  boolean hmacVerify(short opHandle, byte[] keyBuf, short keyStart, short keyLength,
                     byte[] data, short dataStart, short dataLength,
                     byte[] mac, short macStart, short macLength);
  short hmacUpdate(short opHandle, byte[] dataBuf, short dataStart, short dataLength);


  KMCipher createRsaDecipher(short padding,
                             byte[] secret, short secretStart, short secretLength,
                             byte[] modBuffer, short modOff, short modLength);
  Signature createRsaSigner(short msgDigestAlg, short padding, byte[] secret, short secretStart,
                            short secretLength, byte[] modBuffer, short modOff, short modLength);
  Signature createEcSigner(short msgDigestAlg, byte[] secret, short secretStart,
                           short secretLength);
  KMCipher createSymmetricCipher(short cipherAlg, short mode, short padding,
                               byte[] secret, short secretStart, short secretLength,
                               byte[] ivBuffer, short ivStart, short ivLength);
  KMCipher createSymmetricCipher(short cipherAlg, short mode,short padding,
                                 byte[] secret, short secretStart, short secretLength);
  Signature createHmacSignerVerifier(short purpose, short msgDigestAlg,
                                     byte[] secret, short secretStart, short secretLength);
  KMCipher createAesGcmCipher(short mode, short tagLen, byte[] secret, short secretStart, short secretLength,
                              byte[] ivBuffer, short ivStart, short ivLength);
  void delete(KMCipher cipher);
  void delete(Signature signature);
  void delete(Key key);
  void delete(KeyPair keyPair);
  //TODO remove this later
  void bypassAesGcm();

  KMCipher createRsaCipher(short padding, byte[] buffer, short startOff, short length);
  Signature createRsaVerifier(short msgDigestAlg, short padding, byte[] modBuffer,
                              short modOff, short modLength);
  Signature createEcVerifier(short msgDigestAlg, byte[] pubKey, short pubKeyStart, short pubKeyLength);

  short getSystemTimeInMilliSeconds(byte[] timeBuf, short timeStart, short timeOffset);
  short addListener(KMEventListener listener, byte eventType);
  short getEventData(byte[] eventBuf, short eventStart, short eventLength);

  //Capability query - should return true
  boolean isAlgSupported(byte alg);
  boolean isKeySizeSupported(byte alg, short keySize);
  boolean isCurveSupported(byte eccurve);
  boolean isDigestSupported(byte alg, byte digest);
  boolean isPaddingSupported(byte alg, byte padding);
  boolean isBlockModeSupported(byte alg, byte blockMode);

  //Capability query - may return true
  boolean isSystemTimerSupported();
  boolean isBootEventSupported();
}
