package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCosePairSimpleValueTag represents a key-value type, where key can be KMInteger or KMNInteger and value is
 * KMSimpleValue type. struct{byte TAG_TYPE; short length; struct{short SIMPLE_VALUE_TYPE; short key; short value}}.
 */
public class KMCosePairSimpleValueTag extends KMCosePairTagType {

  private static KMCosePairSimpleValueTag prototype;

  private KMCosePairSimpleValueTag() {
  }

  private static KMCosePairSimpleValueTag proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCosePairSimpleValueTag();
    }
    instanceTable[KM_COSE_KEY_SIMPLE_VAL_OFFSET] = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(COSE_PAIR_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), KMType.INVALID_VALUE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), KMSimpleValue.exp());
    return ptr;
  }

  public static short instance(short keyPtr, short valuePtr) {
    short offset = KMCosePairTagType.getKeyStartOffset(keyPtr);
    if (!KMCosePairTagType.isKeyPairValid(heap, offset, KMCose.COSE_KEY_MAX_SIZE,
        KMSimpleValue.cast(valuePtr).getValue())) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short ptr = KMType.instance(COSE_PAIR_TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), keyPtr);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), valuePtr);
    return ptr;
  }

  public static KMCosePairSimpleValueTag cast(short ptr) {
    byte[] heap = repository.getHeap();
    if (heap[ptr] != COSE_PAIR_TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // Validate the value pointer.
    short valuePtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4));
    if (KMType.getType(valuePtr) != SIMPLE_VALUE_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getValueType() {
    return SIMPLE_VALUE_TYPE;
  }

  @Override
  public short getKeyPtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_SIMPLE_VAL_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  @Override
  public short getValuePtr() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_SIMPLE_VAL_OFFSET] + TLV_HEADER_SIZE + 4));
  }

}
