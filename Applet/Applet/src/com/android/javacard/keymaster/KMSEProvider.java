package com.android.javacard.keymaster;

public interface KMSEProvider {
  // Key generation operations
  short createSymmetricKey(byte alg, short keysize, byte[] buf, short startOff);

  void createAsymmetricKey(
      byte alg,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyMaxLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModMaxLength,
      short[] lengths);

  // Import key operations
  boolean importSymmetricKey(byte alg, short keysize, byte[] buf, short startOff, short length);

  boolean importAsymmetricKey(
      byte alg,
      byte[] buf,
      short start,
      short length,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModLength);

  boolean importAsymmetricKey(
    byte alg,
    byte[] privKeyBuf,
    short privKeyStart,
    short privKeyLength,
    byte[] pubModBuf,
    short pubModStart,
    short pubModLength);

  // Oneshot Operations
  void newRandomNumber(byte[] num, short offset, short length);

  void addRngEntropy(byte[] num, short offset, short length);

  byte[] getTrueRandomNumber(short len);

  short aesGCMEncrypt(
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
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
      byte[] aesKey,
      short aesKeyStart,
      short aesKeyLen,
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
    short masterKeyStart, short masterKeyLen, byte[] bufOut,
    short bufStart);

  short cmacKdf(
    byte[] keyMaterial,
    short keyMaterialStart,
    short keyMaterialLen,
    byte[] label,
    byte[] context,
    short contextStart,
    short contextLength,
    byte[] keyBuf,
    short keyStart);

  short hmacSign(
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] mac,
      short macStart);

  boolean hmacVerify(
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] data,
      short dataStart,
      short dataLength,
      byte[] mac,
      short macStart,
      short macLength);

  short rsaDecipherOAEP256(
      byte[] secret,
      short secretStart,
      short secretLength,
      byte[] modBuffer,
      short modOff,
      short modLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart);

  short rsaSignPKCS1256(
      byte[] secret,
      short secretStart,
      short secretLength,
      byte[] modBuffer,
      short modOff,
      short modLength,
      byte[] inputDataBuf,
      short inputDataStart,
      short inputDataLength,
      byte[] outputDataBuf,
      short outputDataStart);

  // Persistent Operations
  KMOperation initSymmetricOperation(
      byte purpose,
      byte alg,
      byte digest,
      byte padding,
      byte blockMode,
      byte[] keyBuf,
      short keyStart,
      short keyLength,
      byte[] ivBuf,
      short ivStart,
      short ivLength,
      short macLength);

  KMOperation initAsymmetricOperation(
      byte purpose,
      byte alg,
      byte padding,
      byte digest,
      byte[] privKeyBuf,
      short privKeyStart,
      short privKeyLength,
      byte[] pubModBuf,
      short pubModStart,
      short pubModLength);

  //X509 Cert
  KMAttestationCert getAttestationCert(boolean rsaCert);

  // Backup and restore
  boolean isBackupRestoreSupported();
  void backup(byte[] buf, short start, short len);
  short restore(byte[] buf, short start);
}