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
package com.android.javacard.kmdevice;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCoseHeaders represents headers section from the Cose standard https://datatracker.ietf.org/doc/html/rfc8152#section-3.
 * The supported key types are KMInteger, KMNInteger and the supported value types are KMInteger,
 * KMNInteger, KMByteBlob, KMCoseKey. It corresponds to a CBOR Map type. struct{byte TAG_TYPE; short
 * length; short arrayPtr }  where arrayPtr is a pointer to array with any KMTag subtype instances.
 */
public class KMCoseHeaders extends KMCoseMap {

  private static KMCoseHeaders prototype;

  private KMCoseHeaders() {
  }

  private static KMCoseHeaders proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseHeaders();
    }
    instanceTable[KM_COSE_HEADERS_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 4);
    // CoseKey is internally an Array so evaluate it separately.
    short coseKeyValueExp = KMCosePairCoseKeyTag.exp();
    KMArray.add(arrPtr, (short) 0, KMCosePairIntegerTag.exp());
    KMArray.add(arrPtr, (short) 1, KMCosePairNegIntegerTag.exp());
    KMArray.add(arrPtr, (short) 2, KMCosePairByteBlobTag.exp());
    KMArray.add(arrPtr, (short) 3, coseKeyValueExp);
    return KMCoseHeaders.instance(arrPtr);
  }


  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_HEADERS_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseHeaders cast(short ptr) {
    if (heap[ptr] != COSE_HEADERS_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short arrPtr = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (heap[arrPtr] != ARRAY_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  @Override
  public short getVals() {
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_HEADERS_OFFSET] + TLV_HEADER_SIZE));
  }

  @Override
  public short length() {
    short arrPtr = getVals();
    return KMArray.length(arrPtr);
  }

  @Override
  public void canonicalize() {
    KMCoseMap.canonicalize(getVals());
  }

  private short getValueType(short key) {
    short index = 0;
    short len = length();
    short arr = getVals();
    short tagType;
    short valPtr = 0;
    short keyPtr;
    boolean found = false;
    while (index < len) {
      tagType = KMCosePairTagType.getTagValueType(KMArray.get(arr, index));
      switch (tagType) {
        case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
          keyPtr = KMCosePairByteBlobTag.cast(KMArray.get(arr, index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairByteBlobTag.cast(KMArray.get(arr, index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_COSE_KEY_TAG_TYPE:
          keyPtr = KMCosePairCoseKeyTag.cast(KMArray.get(arr, index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairCoseKeyTag.cast(KMArray.get(arr, index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_INT_TAG_TYPE:
          keyPtr = KMCosePairIntegerTag.cast(KMArray.get(arr, index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairIntegerTag.cast(KMArray.get(arr, index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
          keyPtr = KMCosePairNegIntegerTag.cast(KMArray.get(arr, index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairNegIntegerTag.cast(KMArray.get(arr, index)).getValuePtr();
            found = true;
          }
          break;
        default:
          break;
      }
      if (found) {
        break;
      }
      index++;
    }
    return valPtr;
  }

  public short getKeyIdentifier() {
    return getValueType(KMCose.COSE_LABEL_KEYID);
  }

  public short getCoseKey() {
    return getValueType(KMCose.COSE_LABEL_COSE_KEY);
  }

  public short getIV() {
    return getValueType(KMCose.COSE_LABEL_IV);
  }

  public short getAlgorithm() {
    return getValueType(KMCose.COSE_LABEL_ALGORITHM);
  }

  public boolean isDataValid(short alg, short keyIdPtr) {
    short[] headerTags = {
        KMCose.COSE_LABEL_ALGORITHM, alg,
        KMCose.COSE_LABEL_KEYID, keyIdPtr,
    };
    boolean valid = false;
    short value;
    short ptr;
    short tagIndex = 0;
    while (tagIndex < headerTags.length) {
      value = headerTags[(short) (tagIndex + 1)];
      if (value != KMType.INVALID_VALUE) {
        valid = false;
        ptr = getValueType(headerTags[tagIndex]);
        switch (KMType.getKMType(ptr)) {
          case KMType.BYTE_BLOB_TYPE:
            if ((KMByteBlob.length(value) == KMByteBlob.length(ptr)) &&
                (0 ==
                    Util.arrayCompare(KMByteBlob.getBuffer(value),
                        KMByteBlob.getStartOff(value),
                        KMByteBlob.getBuffer(ptr),
                        KMByteBlob.getStartOff(ptr),
                        KMByteBlob.length(ptr)))) {
              valid = true;
            }
            break;
          case KMType.INTEGER_TYPE:
            if (value == KMInteger.getShort(ptr)) {
              valid = true;
            }
            break;
          case KMType.NEG_INTEGER_TYPE:
            if ((byte) value == (byte) KMNInteger.getShort(ptr)) {
              valid = true;
            }
            break;
          default:
            break;
        }
        if (!valid) {
          break;
        }
      }
      tagIndex += 2;
    }
    return valid;
  }


}
