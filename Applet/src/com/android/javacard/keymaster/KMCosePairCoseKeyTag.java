package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCosePairCoseKeyTag represents a key-value type, where key can be KMInteger or KMNInteger and value is
 * KMCOseKey type. struct{byte TAG_TYPE; short length; struct{short COSE_KEY_VALUE_TYPE; short key; short value}}.
 */
public class KMCosePairCoseKeyTag extends KMCosePairTagType {

  public static final byte[] keys = {
      KMCose.COSE_LABEL_COSE_KEY
  };
  private static KMCosePairCoseKeyTag prototype;

  private KMCosePairCoseKeyTag() {
  }

  private static KMCosePairCoseKeyTag proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCosePairCoseKeyTag();
    }
    instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_PAIR_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_PAIR_COSE_KEY_TAG_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), KMCoseKey.exp());
    return ptr;
  }

  public static short instance(short keyPtr, short valuePtr) {
    if (!isKeyValueValid(KMCosePairTagType.getKeyValueShort(keyPtr))) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (KMType.getType(valuePtr) != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_PAIR_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_PAIR_COSE_KEY_TAG_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), valuePtr);
    return ptr;
  }

  public static KMCosePairCoseKeyTag cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_PAIR_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the value pointer.
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4));
    if (KMType.getType(valuePtr) != COSE_KEY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getValueType() {
    return COSE_KEY_TYPE;
  }

  @Override
  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  @Override
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_COSE_KEY_VAL_OFFSET] + TLV_HEADER_SIZE + 4));
  }

  public static boolean isKeyValueValid(short keyVal) {
    short index = 0;
    while (index < (short) keys.length) {
      if ((byte) (keyVal & 0xFF) == keys[index])
        return true;
      index++;
    }
    return false;
  }

}
