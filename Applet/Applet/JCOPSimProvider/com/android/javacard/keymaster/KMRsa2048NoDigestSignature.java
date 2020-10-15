package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.MessageDigest;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class KMRsa2048NoDigestSignature extends Signature {
  private Cipher inst; // ALG_RSA_NOPAD.;
  //TODO ??
  //private byte[] rsaModulus; // to compare with the data value
  
  public static final byte ALG_RSA_SIGN_NOPAD = (byte)0x65; //TODO Change value later
  public static final byte ALG_RSA_PKCS1_NODIGEST = (byte)0x66;  //TODO Change value later
  private byte algorithm;
  
  public KMRsa2048NoDigestSignature(byte alg){
    algorithm = alg;
    inst = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
  }

  /*public KMRsa2048NoDigestSignature(Cipher ciph, byte padding, byte[]mod, short start, short len){
    inst = ciph;
    this.padding = padding;
    if(len != 256) CryptoException.throwIt(CryptoException.INVALID_INIT);
    rsaModulus = new byte[256];
    Util.arrayCopyNonAtomic(mod,start,rsaModulus,(short)0,len);
  }*/

  @Override
  public void init(Key key, byte b) throws CryptoException {
    inst.init(key, b);
  }

  @Override
  public void init(Key key, byte b, byte[] bytes, short i, short i1) throws CryptoException {
    inst.init(key, b, bytes, i, i1);
  }

  @Override
  public void setInitialDigest(byte[] bytes, short i, short i1, byte[] bytes1, short i2, short i3) throws CryptoException {
    //TODO
  }

  @Override
  public byte getAlgorithm() {
    return algorithm;
  }

  @Override
  public byte getMessageDigestAlgorithm() {
    return MessageDigest.ALG_NULL;
  }

  @Override
  public byte getCipherAlgorithm() {
    return algorithm;
  }

  @Override
  public byte getPaddingAlgorithm() {
    return Cipher.PAD_NULL;
  }

  @Override
  public short getLength() throws CryptoException {
    return 0;
  }

  @Override
  public void update(byte[] bytes, short i, short i1) throws CryptoException {
    // HAL accumulates the data and send it at finish operation.
  }

  @Override
  public short sign(byte[] bytes, short i, short i1, byte[] bytes1, short i2) throws CryptoException {
    padData(bytes,i,i1, KMJCOPSimProvider.getInstance().tmpArray, (short)0);
    return inst.doFinal(KMJCOPSimProvider.getInstance().tmpArray,(short)0,(short)256, bytes1, i2);
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

  private void padData(byte[] buf, short start, short len,
      byte[] outBuf, short outBufStart){
    //byte[] inputData = new byte[256];
    //TODO ?
    /*if(!isValidData(buf, start,len)){
      CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
    }*/
    Util.arrayFillNonAtomic(outBuf, (short) outBufStart, (short) 256, (byte) 0x00);
    if (algorithm == ALG_RSA_SIGN_NOPAD) { // add zero to right
    } else if (algorithm == ALG_RSA_PKCS1_NODIGEST) {// 0x00||0x01||PS||0x00
      outBuf[0] = 0x00;
      outBuf[1] = 0x01;
      Util.arrayFillNonAtomic(outBuf,(short)2,(short)(256-len-3),(byte)0xFF);
      outBuf[(short)(256-len-1)] = 0x00;
    }else{
      CryptoException.throwIt(CryptoException.ILLEGAL_USE);
    }
    Util.arrayCopyNonAtomic(buf, start, outBuf,(short)(256 -len), len);
  }

  /*private boolean isValidData(byte[] buf, short start, short len) {
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
  }*/
}
