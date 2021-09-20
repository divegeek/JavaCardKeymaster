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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.keymaster;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * KMCoseKey represents COSE_Key section from the Cose standard https://datatracker.ietf.org/doc/html/rfc8152#section-7
 * The supported key types are KMNInteger, KMInteger and the supported value types are KMInteger, KMNInteger,
 * KMByteBlob, KMSimpleValue. It corresponds to a CBOR Map type.  struct{byte TAG_TYPE; short length; short arrayPtr }
 * where arrayPtr is a pointer to array with any KMTag subtype instances.
 */
public class KMCoseKey extends KMCoseMap {

  private static KMCoseKey prototype;

  private KMCoseKey() {
  }

  private static KMCoseKey proto(short ptr) {
    if (prototype == null) {
      prototype = new KMCoseKey();
    }
    instanceTable[KM_COSE_KEY_OFFSET] = ptr;
    return prototype;
  }

  public static short exp() {
    short arrPtr = KMArray.instance((short) 4);
    KMArray arr = KMArray.cast(arrPtr);
    arr.add((short) 0, KMCosePairIntegerTag.exp());
    arr.add((short) 1, KMCosePairNegIntegerTag.exp());
    arr.add((short) 2, KMCosePairByteBlobTag.exp());
    arr.add((short) 3, KMCosePairSimpleValueTag.exp());
    return KMCoseKey.instance(arrPtr);
  }


  public static short instance(short vals) {
    short ptr = KMType.instance(COSE_KEY_TYPE, (short) 2);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), vals);
    return ptr;
  }

  public static KMCoseKey cast(short ptr) {
    if (heap[ptr] != COSE_KEY_TYPE) {
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
    return Util.getShort(heap, (short) (instanceTable[KM_COSE_KEY_OFFSET] + TLV_HEADER_SIZE));
  }

  @Override
  public short length() {
    short arrPtr = getVals();
    return KMArray.cast(arrPtr).length();
  }

  private short getValueType(short key, short significantKey) {
    short arr = getVals();
    short length = length();
    short keyPtr;
    short valPtr = 0;
    short index = 0;
    short tagType;
    boolean found = false;
    while (index < length) {
      tagType = KMCosePairTagType.getTagValueType(KMArray.cast(arr).get(index));
      switch (tagType) {
        case KMType.COSE_PAIR_BYTE_BLOB_TAG_TYPE:
          keyPtr = KMCosePairByteBlobTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairByteBlobTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_INT_TAG_TYPE:
          keyPtr = KMCosePairIntegerTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairIntegerTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_NEG_INT_TAG_TYPE:
          keyPtr = KMCosePairNegIntegerTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == (byte) KMCosePairTagType.getKeyValueShort(keyPtr)) {
            valPtr = KMCosePairNegIntegerTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        case KMType.COSE_PAIR_SIMPLE_VALUE_TAG_TYPE:
          keyPtr = KMCosePairSimpleValueTag.cast(KMArray.cast(arr).get(index)).getKeyPtr();
          if (key == KMCosePairTagType.getKeyValueShort(keyPtr) &&
              significantKey == KMCosePairTagType.getKeyValueSignificantShort(keyPtr)) {
            valPtr = KMCosePairSimpleValueTag.cast(KMArray.cast(arr).get(index)).getValuePtr();
            found = true;
          }
          break;
        default:
          break;

      }
      if (found)
        break;
      index++;
    }
    return valPtr;
  }

  public short getKeyIdentifier() {
    return getValueType(KMCose.COSE_KEY_KEY_ID, KMType.INVALID_VALUE);
  }

  public short getEcdsa256PublicKey(byte[] pubKey, short pubKeyOff) {
    short baseOffset = pubKeyOff;
    pubKey[pubKeyOff] = (byte) 0x04; // uncompressed.
    pubKeyOff++;
    short ptr = getValueType(KMCose.COSE_KEY_PUBKEY_X, KMType.INVALID_VALUE);
    Util.arrayCopy(KMByteBlob.cast(ptr).getBuffer(), KMByteBlob.cast(ptr).getStartOff(),
        pubKey, pubKeyOff, KMByteBlob.cast(ptr).length());
    pubKeyOff += KMByteBlob.cast(ptr).length();
    ptr = getValueType(KMCose.COSE_KEY_PUBKEY_Y, KMType.INVALID_VALUE);
    Util.arrayCopy(KMByteBlob.cast(ptr).getBuffer(), KMByteBlob.cast(ptr).getStartOff(),
        pubKey, pubKeyOff, KMByteBlob.cast(ptr).length());
    pubKeyOff += KMByteBlob.cast(ptr).length();
    return (short) (pubKeyOff - baseOffset);
  }

  public short getPrivateKey(byte[] priv, short privOff) {
    short ptr = getValueType(KMCose.COSE_KEY_PRIV_KEY, KMType.INVALID_VALUE);
    Util.arrayCopy(KMByteBlob.cast(ptr).getBuffer(), KMByteBlob.cast(ptr).getStartOff(),
        priv, privOff, KMByteBlob.cast(ptr).length());
    return KMByteBlob.cast(ptr).length();
  }

  public boolean isTestKey() {
    short ptr =
        getValueType(
            Util.getShort(KMCose.COSE_TEST_KEY, (short) 2), // LSB
            Util.getShort(KMCose.COSE_TEST_KEY, (short) 0) // MSB (Significant)
        );
    boolean isTestKey = false;
    if (ptr != 0)
      isTestKey = (KMSimpleValue.cast(ptr).getValue() == KMSimpleValue.NULL);
    return isTestKey;
  }

  /**
   * Verifies the KMCoseKey values against the input values.
   *
   * @param keyType  value of the key type
   * @param keyIdPtr instance of KMByteBlob containing the key id.
   * @param keyAlg   value of the algorithm.
   * @param keyOps   value of the key operations.
   * @param curve    value of the curve.
   * @return true if valid, otherwise false.
   */
  public boolean isDataValid(short keyType, short keyIdPtr, short keyAlg, short keyOps, short curve) {
    short[] coseKeyTags = {
        KMCose.COSE_KEY_KEY_TYPE, keyType,
        KMCose.COSE_KEY_KEY_ID, keyIdPtr,
        KMCose.COSE_KEY_ALGORITHM, keyAlg,
        KMCose.COSE_KEY_KEY_OPS, keyOps,
        KMCose.COSE_KEY_CURVE, curve,
    };
    boolean valid = false;
    short ptr;
    short tagIndex = 0;
    short value;
    while (tagIndex < coseKeyTags.length) {
      value = coseKeyTags[(short) (tagIndex + 1)];
      if (value != KMType.INVALID_VALUE) {
        valid = false;
        ptr = getValueType(coseKeyTags[tagIndex], KMType.INVALID_VALUE);
        switch (KMType.getType(ptr)) {
          case KMType.BYTE_BLOB_TYPE:
            if ((KMByteBlob.cast(value).length() == KMByteBlob.cast(ptr).length()) &&
                (0 ==
                    Util.arrayCompare(KMByteBlob.cast(value).getBuffer(),
                        KMByteBlob.cast(value).getStartOff(),
                        KMByteBlob.cast(ptr).getBuffer(),
                        KMByteBlob.cast(ptr).getStartOff(),
                        KMByteBlob.cast(ptr).length()))) {
              valid = true;
            }
            break;
          case KMType.INTEGER_TYPE:
            if (value == KMInteger.cast(ptr).getShort()) {
              valid = true;
            }
            break;
          case KMType.NEG_INTEGER_TYPE:
            if ((byte) value == (byte) KMNInteger.cast(ptr).getShort()) {
              valid = true;
            }
            break;
        }
        if (!valid)
          break;
      }
      tagIndex += 2;
    }
    return valid;
  }

  @Override
  public void canonicalize() {
    KMCoseMap.canonicalize(getVals());
  }

}
