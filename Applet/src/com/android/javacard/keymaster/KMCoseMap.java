/*
 * Copyright(C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * This class represents either a Cose_key or Cose headers as defined in https://datatracker.ietf.org/doc/html/rfc8152
 * This is basically a map containing key value pairs. The label for the key can be (uint / int / tstr) and
 * the value can be of any type. But this class is confined to support only key and value types which are
 * required for remote key provisioning. So keys of type (int / uint) and values of type (int / uint / simple / bstr)
 * only are supported. KMCoseHeaders and KMCoseKey implements this class.
 */
public abstract class KMCoseMap extends KMType {

  public static byte[] scratchpad;

  /**
   * This function creates an instance of either KMCoseHeaders or KMCoseKey based on the type information
   * provided.
   *
   * @param typePtr type information of the underlying KMType.
   * @param arrPtr  instance of KMArray.
   * @return instance type of either KMCoseHeaders or KMCoseKey.
   */
  public static short createInstanceFromType(short typePtr, short arrPtr) {
    short mapType = KMType.getType(typePtr);
    switch (mapType) {
      case KMType.COSE_HEADERS_TYPE:
        return KMCoseHeaders.instance(arrPtr);
      case KMType.COSE_KEY_TYPE:
        return KMCoseKey.instance(arrPtr);
      case KMType.COSE_CERT_PAYLOAD_TYPE:
        return KMCoseCertPayload.instance(arrPtr);
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  public static short getVals(short ptr) {
    short mapType = KMType.getType(ptr);
    switch (mapType) {
      case KMType.COSE_HEADERS_TYPE:
        return KMCoseHeaders.cast(ptr).getVals();
      case KMType.COSE_KEY_TYPE:
        return KMCoseKey.cast(ptr).getVals();
      case KMType.COSE_CERT_PAYLOAD_TYPE:
        return KMCoseCertPayload.cast(ptr).getVals();
      default:
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        return 0;
    }
  }

  abstract public short getVals();

  abstract public short length();

  abstract public void canonicalize();

  private static short getKey(short tagPtr) {
    short tagType = KMCosePairTagType.getTagValueType(tagPtr);
    switch (tagType) {
      case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
        return KMCosePairByteBlobTag.cast(tagPtr).getKeyPtr();
      case KMType.COSE_PAIR_INT_TAG_TYPE:
        return KMCosePairIntegerTag.cast(tagPtr).getKeyPtr();
      case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
        return KMCosePairNegIntegerTag.cast(tagPtr).getKeyPtr();
      case KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE:
        return KMCosePairSimpleValueTag.cast(tagPtr).getKeyPtr();
      case KMType.COSE_PAIR_COSE_KEY_TAG_TYPE:
        return KMCosePairCoseKeyTag.cast(tagPtr).getKeyPtr();
      case KMType.COSE_PAIR_TEXT_STR_TAG_TYPE:
        return KMCosePairTextStringTag.cast(tagPtr).getKeyPtr();
      default:
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return 0;
  }

  private static void createScratchBuffer() {
    if (scratchpad == null)
      scratchpad = JCSystem.makeTransientByteArray((short) 120, JCSystem.CLEAR_ON_RESET);
  }

  // Bubble sort.
  public static void canonicalizeCborMap(short map) {
    short index = 0;
    short innerIndex;
    short length = KMMap.cast(map).length();
    short firstKey;
    short secondKey;
    short firstKeyLen;
    short secondKeyLen;
    createScratchBuffer();
    boolean flag = false;
    while (index < length) {
      innerIndex = 0;
      while (innerIndex < (short) (length - index - 1)) {
        firstKey = KMMap.cast(map).getKey(innerIndex);
        firstKeyLen = KMKeymasterApplet.encoder.encode(firstKey, scratchpad, (short) 0);
        secondKey = KMMap.cast(map).getKey((short) (innerIndex + 1));
        secondKeyLen = KMKeymasterApplet.encoder.encode(secondKey, scratchpad, firstKeyLen);
        if ((firstKeyLen > secondKeyLen) ||
          ((firstKeyLen == secondKeyLen) &&
            (0 < Util.arrayCompare(scratchpad, (short) 0, scratchpad, firstKeyLen, firstKeyLen)))) {
          KMMap.cast(map).swap(innerIndex, (short) (innerIndex + 1));
          flag = true;
        }
        innerIndex++;
      }
      if (!flag)
        break;
      index++;
    }
  }
  // Bubble sort
  protected static void canonicalize(short arr) {
    short index = 0;
    short innerIndex;
    short length = KMArray.cast(arr).length();
    short firstKey;
    short secondKey;
    short firstKeyLen;
    short secondKeyLen;
    createScratchBuffer();
    boolean flag = false;
    while (index < length) {
      innerIndex = 0;
      while (innerIndex < (short) (length - index - 1)) {
        firstKey = getKey(KMArray.cast(arr).get(innerIndex));
        firstKeyLen = KMKeymasterApplet.encoder.encode(firstKey, scratchpad, (short) 0);
        secondKey = getKey(KMArray.cast(arr).get((short) (innerIndex + 1)));
        secondKeyLen = KMKeymasterApplet.encoder.encode(secondKey, scratchpad, firstKeyLen);
        if ((firstKeyLen > secondKeyLen) ||
            ((firstKeyLen == secondKeyLen) &&
                (0 < Util.arrayCompare(scratchpad, (short) 0, scratchpad, firstKeyLen, firstKeyLen)))) {
          KMArray.cast(arr).swap(innerIndex, (short) (innerIndex + 1));
          flag = true;
        }
        innerIndex++;
      }
      if (!flag)
        break;
      index++;
    }
  }
}