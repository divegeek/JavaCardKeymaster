package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


public class KMCipherImpl extends KMCipher{
  Cipher cipher;
  javax.crypto.Cipher sunCipher;
  short cipherAlg;
  short paddingAlg;
  short mode;
  boolean verificationFlag;
  KMCipherImpl(Cipher c){
    cipher = c;
  }
  KMCipherImpl(javax.crypto.Cipher c){sunCipher = c;}

  @Override
  public short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i){
    if(cipherAlg == KMCipher.CIPHER_RSA &&
      (paddingAlg == KMCipher.PAD_PKCS1_OAEP_SHA256||paddingAlg == KMCipher.PAD_PKCS1_OAEP)){
      try {
        return (short)sunCipher.doFinal(buffer,startOff,length,scratchPad,i);
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
    }else if(cipherAlg == KMCipher.ALG_AES_GCM){
      try {
        return (short)sunCipher.doFinal(buffer,startOff,length,scratchPad,i);
      } catch (AEADBadTagException e) {
        e.printStackTrace();
        verificationFlag = false;
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (IllegalBlockSizeException e) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      } catch (BadPaddingException e) {
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else {
      short len = cipher.doFinal(buffer, startOff, length, scratchPad, i);
      // JCard Sim removes leading zeros during decryption in case of no padding - we add that back.
      if (cipherAlg == Cipher.ALG_RSA_NOPAD && mode == Cipher.MODE_DECRYPT && len < 256) {
        byte[] tempBuf = new byte[256];
        Util.arrayFillNonAtomic(tempBuf, (short) 0, (short) 256, (byte) 0);
        Util.arrayCopyNonAtomic(scratchPad, (short) 0, tempBuf, (short) (i + 256 - len), len);
        Util.arrayCopyNonAtomic(tempBuf, (short) 0, scratchPad, i, (short) 256);
        len = 256;
      }
      return len;
    }
    return KMType.INVALID_VALUE;
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
    if(cipherAlg == KMCipher.ALG_AES_GCM){
      try {
        return (short)sunCipher.update(buffer,startOff,length,scratchPad,i);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else {
      return cipher.update(buffer, startOff, length, scratchPad, i);
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public void updateAAD(byte[] buffer, short startOff, short length) {
    sunCipher.updateAAD(buffer,startOff,length);
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
