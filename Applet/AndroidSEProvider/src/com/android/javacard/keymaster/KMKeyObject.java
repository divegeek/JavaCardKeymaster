package com.android.javacard.keymaster;

public class KMKeyObject {
  private byte algorithm;
  private Object keyObjectInst;

  public void setKeyObjectData(byte alg, Object keyObject) {
    algorithm = alg;
    keyObjectInst = keyObject;
  }

  public byte getAlgorithm() {
    return this.algorithm;
  }

  public Object getKeyObjectInstance() {
    return keyObjectInst;
  }
}
