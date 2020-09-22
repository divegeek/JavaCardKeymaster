package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class KMRsa2048NoDigestSignature extends Signature {
  private Cipher inst; // ALG_RSA_NOPAD.
  private byte padding;
  private byte[] rsaModulus; // to compare with the data value

  public KMRsa2048NoDigestSignature(Cipher ciph, byte padding, byte[]mod, short start, short len){
    inst = ciph;
    this.padding = padding;
    if(len != 256) CryptoException.throwIt(CryptoException.INVALID_INIT);
    rsaModulus = new byte[256];
    Util.arrayCopyNonAtomic(mod,start,rsaModulus,(short)0,len);
  }

  @Override
  public void init(Key key, byte b) throws CryptoException {

  }

  @Override
  public void init(Key key, byte b, byte[] bytes, short i, short i1) throws CryptoException {
  }

  @Override
  public void setInitialDigest(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
  }

  @Override
  public byte getAlgorithm() {
    return 0;
  }

  @Override
  public byte getMessageDigestAlgorithm() {
    return 0;
  }

  @Override
  public byte getCipherAlgorithm() {
    return 0;
  }

  @Override
  public byte getPaddingAlgorithm() {
    return 0;
  }

  @Override
  public short getLength() throws CryptoException {
    return 0;
  }

  @Override
  public void update(byte[] bytes, short i, short i1) throws CryptoException {
  }

  @Override
  public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
    byte[] inputData = padData(bytes,i,i1);
    return inst.doFinal(inputData,(short)0,(short)256,bytes1,i2);
  }

  @Override
  public short signPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
    return 0;
  }

  @Override
  public boolean verify(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
    // Cannot support this method as javacard cipher api does not allow 256 byte for public key
    // encryption without padding. It only allows 255 bytes data.
    return false;
  }

  @Override
  public boolean verifyPreComputedHash(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
    return false;
  }

  private byte[] padData(byte[] buf, short start, short len){
    byte[] inputData = new byte[256];
    if(!isValidData(buf, start,len)){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }
    Util.arrayFillNonAtomic(inputData, (short) 0, (short) 256, (byte) 0x00);
    if (padding == KMType.PADDING_NONE) { // add zero to right
    } else if (padding == KMType.RSA_PKCS1_1_5_SIGN) {// 0x00||0x01||PS||0x00
      inputData[0] = 0x00;
      inputData[1] = 0x01;
      Util.arrayFillNonAtomic(inputData,(short)2,(short)(256-len-3),(byte)0xFF);
      inputData[(short)(256-len-1)] = 0x00;
    }else{
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }
    Util.arrayCopyNonAtomic(buf,start,inputData,(short)(256 -len),len);
    return inputData;
  }

  private boolean isValidData(byte[] buf, short start, short len) {
    if (padding == KMType.PADDING_NONE) {
      if (len > 256) return false;
      else if (len == 256) {
        short v = Util.arrayCompare(buf, start, rsaModulus, (short) 0, len);
        if (v > 0) return false;
      }
    } else {//pkcs1 no digest
      if(len > 245){
        return false;
      }
    }
    return true;
  }
}
