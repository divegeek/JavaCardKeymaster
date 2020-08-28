package com.android.javacard.keymaster;

import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.crypto.Cipher;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;


public class KMCipherImpl extends KMCipher{
  private Cipher cipher;
  private javax.crypto.Cipher sunCipher;
  private short cipherAlg;
  private short paddingAlg;
  private short mode;
  private boolean verificationFlag;
  public static short aes_gcm_decrypt_final_data = 0x00;

  KMCipherImpl(Cipher c){
    cipher = c;
  }
  KMCipherImpl(javax.crypto.Cipher c){
    sunCipher = c;
  }

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
        /*
    	  if (mode == javax.crypto.Cipher.DECRYPT_MODE) {
    	    short acutalLen = (short)sunCipher.getOutputSize(length);
    	    aes_gcm_decrypt_final_data = KMByteBlob.instance(acutalLen);
    	    return (short)sunCipher.doFinal(buffer,startOff,length,
    	    		KMByteBlob.cast(aes_gcm_decrypt_final_data).getBuffer(),
    	    		KMByteBlob.cast(aes_gcm_decrypt_final_data).getStartOff());
    	  }
      */
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
    } else if(cipherAlg == KMCipher.ALG_AES_CTR){
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
    }
    else{
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
    short len = 0;
    if(cipherAlg == KMCipher.ALG_AES_GCM || cipherAlg == KMCipher.ALG_AES_CTR){
      try {
        return (short)sunCipher.update(buffer,startOff,length,scratchPad,i);
      } catch (ShortBufferException e) {
        e.printStackTrace();
        CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
      }
    } else{
      return cipher.update(buffer, startOff, length, scratchPad, i);
    }
    return KMType.INVALID_VALUE;
  }

  @Override
  public void updateAAD(byte[] buffer, short startOff, short length) {
	  try {
    sunCipher.updateAAD(buffer,startOff,length);
	  } catch (IllegalArgumentException e) {
		  e.printStackTrace();
		  CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
	  } catch (IllegalStateException e) {
		  CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
	  } catch (UnsupportedOperationException e) {
		  CryptoException.throwIt(CryptoException.ILLEGAL_USE);
	  }
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

  @Override
  public short getCipherProvider() {
	  return KMCipher.SUN_JCE;
  }

  @Override
  public short getAesGcmOutputSize(short len, short macLength) {
    if (sunCipher != null) {
      return (short) sunCipher.getOutputSize(len);
    } else {
      if (mode == KMType.ENCRYPT) {
        return (short) (len + macLength);
      } else {
        return (short) (len - macLength);
      }
    }
  }
}
