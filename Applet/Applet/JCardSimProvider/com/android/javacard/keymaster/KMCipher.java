package com.android.javacard.keymaster;

public abstract class KMCipher {
  /*
  public static final byte CIPHER_RSA = 7;
  public static final short PAD_PKCS1_OAEP = 9;
  public static final short PAD_PKCS1_OAEP_SHA224 = 13;
  public static final byte PAD_PKCS1_OAEP_SHA256 = 14;
  public static final short PAD_PKCS1_OAEP_SHA384 = 15;
  public static final short PAD_PKCS1_OAEP_SHA512 = 16;
  public static final short PAD_NOPAD = 1;
  public static final short PAD_PKCS1_PSS = 8;
  public static final short PAD_NULL = 0;
  public static final short PAD_PKCS7 = 31; // Not supported in javacard
  public static final short ALG_DES_CBC_NOPAD = 1;
  public static final short ALG_DES_ECB_NOPAD = 5;
  public static final short ALG_AES_BLOCK_128_CBC_NOPAD= 13;
  public static final short ALG_AES_BLOCK_128_ECB_NOPAD = 14;
  public static final short ALG_AES_GCM = -13;
  public static final short MODE_ENCRYPT = 2;
  public static final short MODE_DECRYPT = 1;
  public static final short PAD_PKCS1 = 7;
  public static final short AES_BLOCK_SIZE = 16;
  public static final short DES_BLOCK_SIZE = 8;
  public static final short ALG_AES_CTR = -16;

   */
  public static final short SUN_JCE = 0xE9;

  public abstract short doFinal(byte[] buffer, short startOff, short length, byte[] scratchPad, short i);

  public abstract short update(byte[] buffer, short startOff, short length, byte[] scratchPad, short i);

  public abstract void updateAAD(byte[] buffer, short startOff, short length);

  public abstract short getBlockMode();

  public abstract void setBlockMode(short mode);

  public abstract short getPaddingAlgorithm();

  public abstract short getCipherAlgorithm();

  public abstract void setPaddingAlgorithm(short alg);

  public abstract void setCipherAlgorithm(short alg);

  public abstract short getCipherProvider();

  public abstract short getAesGcmOutputSize(short len, short macLength);
}
