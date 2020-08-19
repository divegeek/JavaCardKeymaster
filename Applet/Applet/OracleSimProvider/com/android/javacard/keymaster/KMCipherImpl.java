package com.android.javacard.keymaster;

import com.android.javacard.keymaster.KMCipher;
import javacardx.crypto.Cipher;

public class KMCipherImpl extends KMCipher{
  Cipher cipher;
  short cipherAlg;
  short paddingAlg;
  KMCipherImpl(Cipher c){
    cipher = c;
  }

  @Override
  public short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    return cipher.doFinal(buffer, startOff, length, scratchPad, i);
  }

  @Override
  public short getCipherAlgorithm() {
    return cipher.getCipherAlgorithm();
  }


  @Override
  public void setPaddingAlgorithm(short alg) {
    paddingAlg = alg;
  }

  @Override
  public void setCipherAlgorithm(short alg) {
    cipherAlg = alg;
  }

  @Override
  public short getCipherProvider() {
    return 0;
  }

  @Override
  public short getAesGcmOutputSize(short len, short macLength) {
    return len;
  }

  @Override
  public short update(byte[] buffer, short startOff, short length, byte[] scratchPad, short i) {
    return cipher.update(buffer,startOff,length,scratchPad,i);
  }
  @Override
  public void updateAAD(byte[] buffer, short startOff, short length) {
  }

  @Override
  public short getPaddingAlgorithm() {
    return cipher.getPaddingAlgorithm();
  }
}
