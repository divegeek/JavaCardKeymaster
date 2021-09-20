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
 * This class represents the COSE_Key as defined in https://datatracker.ietf.org/doc/html/rfc8152#section-7.
 * This is basically a map containing key value pairs. The label for the key can be (uint / int / tstr) and
 * the value can be of any type. But this class is confined to support only key and value types which are
 * required for remote key provisioning. So keys of type (int / uint) and values of type (int / uint / simple / bstr)
 * only are supported. The structure representing all the sub classes of KMCosePairTagType is as follows:
 * KM_COSE_PAIR_TAG_TYPE(1byte), Length(2 bytes), COSE_PAIR_*_TAG_TYPE(2 bytes), Key(2 bytes), Value(2 bytes).
 * Key can be either KMInteger or KMNInteger and Value can be either KMIntger or KMNinteger or KMSimpleValue
 * or KMByteBlob or KMTextString or KMCoseKey. Each subclass of KMCosePairTagType is named after their corresponding
 * value type of the Cose pair.
 */
public abstract class KMCosePairTagType extends KMType {

  /**
   * Below table represents the allowed values for a key. The maximum length of the key
   * can be 4 bytes so each key is represented as 4 bytes. The allowed values are
   * placed next to their corresponding key.
   */
  public static Object[] allowedKeyPairs;

  private static void createAllowedKeyPairs() {
    if (allowedKeyPairs == null) {
      allowedKeyPairs =
          new Object[]{
              // Key type
              (Object) new byte[]{0, 0, 0, KMCose.COSE_KEY_KEY_TYPE}, (Object) new byte[]{KMCose.COSE_KEY_TYPE_EC2,
              KMCose.COSE_KEY_TYPE_SYMMETRIC_KEY},
              // Key Algorithm
              (Object) new byte[]{0, 0, 0, KMCose.COSE_KEY_ALGORITHM},
              (Object) new byte[]{KMCose.COSE_ALG_AES_GCM_256, KMCose.COSE_ALG_HMAC_256,
                  KMCose.COSE_ALG_ECDH_ES_HKDF_256, KMCose.COSE_ALG_ES256},
              // Key operations
              (Object) new byte[]{0, 0, 0, KMCose.COSE_KEY_KEY_OPS}, (Object) new byte[]{KMCose.COSE_KEY_OP_SIGN, KMCose.COSE_KEY_OP_VERIFY,
              KMCose.COSE_KEY_OP_ENCRYPT, KMCose.COSE_KEY_OP_DECRYPT},
              // Key Curve
              (Object) new byte[]{0, 0, 0, KMCose.COSE_KEY_CURVE}, (Object) new byte[]{KMCose.COSE_ECCURVE_256},
              // Header Label Algorithm
              (Object) new byte[]{0, 0, 0, KMCose.COSE_LABEL_ALGORITHM}, (Object) new byte[]{KMCose.COSE_ALG_AES_GCM_256,
              KMCose.COSE_ALG_HMAC_256, KMCose.COSE_ALG_ES256, KMCose.COSE_ALG_ECDH_ES_HKDF_256},
              // Test Key
              KMCose.COSE_TEST_KEY, (Object) new byte[]{KMSimpleValue.NULL},
          };
    }
  }


  /**
   * Validates the key and the values corresponding to key.
   *
   * @param key    Buffer containing the key.
   * @param keyOff Offset in the buffer from where key starts.
   * @param keyLen Length of the key buffer.
   * @param value  Value corresponding to the key.
   * @return true if key pair is valid, otherwise false.
   */
  public static boolean isKeyPairValid(byte[] key, short keyOff, short keyLen, short value) {
    short index = 0;
    short valueIdx;
    byte[] values;
    boolean valid = false;
    createAllowedKeyPairs();
    while (index < allowedKeyPairs.length) {
      valueIdx = 0;
      if (isEqual((byte[]) allowedKeyPairs[index], (short) 0, (short) ((byte[]) allowedKeyPairs[index]).length,
          key, keyOff, keyLen)) {
        values = (byte[]) allowedKeyPairs[(short) (index + 1)];
        while (valueIdx < values.length) {
          if (values[valueIdx] == (byte) value) {
            valid = true;
            break;
          }
          valueIdx++;
        }
        if (valid)
          break;
      }
      index += (short) 2;
    }
    return valid;
  }

  /**
   * Compares two key buffers.
   *
   * @param key1    First buffer containing the key.
   * @param offset1 Offset of the first buffer.
   * @param length1 Length of the first buffer.
   * @param key2    Second buffer containing the key.
   * @param offset2 Offset of the second buffer.
   * @param length2 Length of the second buffer.
   * @return true if both keys are equal, otherwise false.
   */
  private static boolean isEqual(byte[] key1, short offset1, short length1, byte[] key2, short offset2,
                                 short length2) {
    if (length1 != length2)
      return false;
    return (0 == KMInteger.unsignedByteArrayCompare(key1, offset1, key2, offset2, length1));
  }

  /**
   * Returns the short value of the key.
   *
   * @param keyPtr Pointer to either KMInteger or KMNInteger
   * @return value of the key as short.
   */
  public static short getKeyValueShort(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short value = 0;
    if (type == INTEGER_TYPE) {
      value = KMInteger.cast(keyPtr).getShort();
    } else if (type == NEG_INTEGER_TYPE) {
      value = KMNInteger.cast(keyPtr).getShort();
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return value;
  }

  /**
   * Returns the significant short value of the key.
   *
   * @param keyPtr Pointer to either KMInteger or KMNInteger
   * @return value of the key as short.
   */
  public static short getKeyValueSignificantShort(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short value = 0;
    if (type == INTEGER_TYPE) {
      value = KMInteger.cast(keyPtr).getSignificantShort();
    } else if (type == NEG_INTEGER_TYPE) {
      value = KMNInteger.cast(keyPtr).getSignificantShort();
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return value;
  }

  public static void getKeyValue(short keyPtr, byte[] dest, short offset, short len) {
    short type = KMType.getType(keyPtr);
    if (type == INTEGER_TYPE) {
      KMInteger.cast(keyPtr).getValue(dest, offset, len);
    } else if (type == NEG_INTEGER_TYPE) {
      KMNInteger.cast(keyPtr).getValue(dest, offset, len);
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
  }

  /**
   * Returns the key offset from the key pointer.
   *
   * @param keyPtr Pointer to either KMInteger or KMNInteger
   * @return offset from where the key starts.
   */
  public static short getKeyStartOffset(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short offset = 0;
    if (type == INTEGER_TYPE) {
      offset = KMInteger.cast(keyPtr).getStartOff();
    } else if (type == NEG_INTEGER_TYPE) {
      offset = KMNInteger.cast(keyPtr).getStartOff();
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return offset;
  }

  /**
   * Returns the key length.
   *
   * @param keyPtr pointer to either KMInteger/KMInteger.
   * @return length of the key.
   */
  public static short getKeyLength(short keyPtr) {
    short type = KMType.getType(keyPtr);
    short len = 0;
    if (type == INTEGER_TYPE) {
      len = KMInteger.cast(keyPtr).length();
    } else if (type == NEG_INTEGER_TYPE) {
      len = KMNInteger.cast(keyPtr).length();
    } else {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return len;
  }

  /**
   * This function returns one of COSE_KEY_TAG_*_VALUE_TYPE tag
   * information.
   *
   * @param ptr Pointer to one of the KMCoseKey*Value class.
   * @return Tag value type.
   */
  public static short getTagValueType(short ptr) {
    return Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
  }

  /**
   * This function returns the key pointer.
   *
   * @return key pointer.
   */
  public abstract short getKeyPtr();

  /**
   * This function returns the value pointer.
   *
   * @return value pointer.
   */
  public abstract short getValuePtr();
}
