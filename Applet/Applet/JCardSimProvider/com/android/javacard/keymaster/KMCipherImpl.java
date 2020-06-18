package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;


public class KMCipherImpl extends KMCipher{
  Cipher cipher;
  short cipherAlg;
  short paddingAlg;
  short mode;
  KMCipherImpl(Cipher c){
    cipher = c;
  }

  @Override
  public short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    short len = cipher.doFinal(buffer, startOff, length, scratchPad, i);
    // JCard Sim removes leading zeros during decryption in case of no padding - we add that back.
    // TODO confirm whether this is fine to pass the VTS.
    if(cipherAlg == Cipher.ALG_RSA_NOPAD &&
      mode == Cipher.MODE_DECRYPT &&
    len < 256){
      byte[] tempBuf = new byte[256];
      Util.arrayFillNonAtomic(tempBuf,(short)0, (short)256, (byte)0);
      Util.arrayCopyNonAtomic(scratchPad,(short)0,tempBuf, (short)(i+256-len),len );
      Util.arrayCopyNonAtomic(tempBuf,(short)0,scratchPad,i,(short)256);
      len = 256;
    }
    return len;
  }

  @Override
  public short getCipherAlgorithm() {
    return cipherAlg;
  }

  @Override
  public void setCipherAlgorithm(short alg) {
    cipherAlg = alg;
  }
  @Override
  public short update(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    return cipher.update(buffer,startOff,length,scratchPad,i);
  }

  @Override
  public short getPaddingAlgorithm() {
    return paddingAlg;
  }

  @Override
  public void setPaddingAlgorithm(short alg) {
    paddingAlg = alg;
  }

  public short getMode() {
    return mode;
  }

  public void setMode(short mode) {
    this.mode = mode;
  }
}
