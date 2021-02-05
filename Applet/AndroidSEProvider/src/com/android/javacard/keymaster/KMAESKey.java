package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;

import com.android.javacard.keymaster.KMMasterKey;

import javacard.security.AESKey;

public class KMAESKey implements KMMasterKey {
  private AESKey aesKey;

  public KMAESKey(AESKey key) {
    aesKey = key;
  }

  public void setKey(byte[] keyData, short kOff) {
    aesKey.setKey(keyData, kOff);
  }

  public AESKey getKey() {
    return aesKey;
  }
  
  public short getKeySizeBits() {
    return aesKey.getSize();
  }

  public static void onSave(Element element, KMAESKey kmKey) {
    element.write(kmKey.aesKey);
  }

  public static KMAESKey onRestore(Element element) {
    AESKey aesKey = (AESKey) element.readObject();
    KMAESKey kmKey = new KMAESKey(aesKey);
    return kmKey;
  }

  public static short getBackupPrimitiveByteCount() {
    return (short) 0;
  }

  public static short getBackupObjectCount() {
    return (short) 1;
  }

}
