package com.android.javacard.keymaster;

public abstract class KMCipher {

  public static final byte CIPHER_RSA = 7;

  public static final short PAD_PKCS1_OAEP_SHA224 = 13;
  public static final byte PAD_PKCS1_OAEP_SHA256 = 14;
  public static final short PAD_PKCS1_OAEP_SHA384 = 15;
  public static final short PAD_PKCS1_OAEP_SHA512 = 16;
  public static final short PAD_NOPAD = 1;
  public static final short PAD_NULL = 0;
  public static final short PAD_PKCS7 = 31; // Not supported in javacard
  public static final short CIPHER_DES_CBC = 3;
  public static final short CIPHER_DES_ECB = 4;
  public static final short CIPHER_AES_CBC = 1;
  public static final short CIPHER_AES_ECB = 2;
  public static final short MODE_ENCRYPT = 2;
  public static final short MODE_DECRYPT = 1;
  public static final short PAD_PKCS1 = 7;

  public abstract short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i);

  public abstract short getCipherAlgorithm();

  public abstract short update(byte[] buffer, short startOff, short length, byte[] scratchPad, short i);

  public abstract short getPaddingAlgorithm();

}
