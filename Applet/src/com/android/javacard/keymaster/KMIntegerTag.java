/*
 * Copyright(C) 2020 The Android Open Source Project
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
 * KMIntegerTag represents UINT, ULONG and DATE tags specified in keymaster hal specs. struct{byte
 * TAG_TYPE; short length; struct{short UINT_TAG/ULONG_TAG/DATE_TAG; short tagKey; 4 or 8 byte
 * value}}
 */
public class KMIntegerTag extends KMTag {

  private static KMIntegerTag prototype;
  // Allowed tag keys.
  private static final short[] tags = {
    // UINT
    KEYSIZE,
    MIN_MAC_LENGTH,
    MIN_SEC_BETWEEN_OPS,
    MAX_USES_PER_BOOT,
    USERID,
    AUTH_TIMEOUT,
    OS_VERSION,
    OS_PATCH_LEVEL,
    VENDOR_PATCH_LEVEL,
    BOOT_PATCH_LEVEL,
    MAC_LENGTH,
    // ULONG
    RSA_PUBLIC_EXPONENT,
    // DATE
    ACTIVE_DATETIME,
    ORIGINATION_EXPIRE_DATETIME,
    USAGE_EXPIRE_DATETIME,
    CREATION_DATETIME
  };

  private KMIntegerTag() {
  }

  private static KMIntegerTag proto(short ptr) {
    if (prototype == null) {
      prototype = new KMIntegerTag();
    }
    instanceTable[KM_INTEGER_TAG_OFFSET] = ptr;
    return prototype;
  }

  public static short exp(short tagType) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short intPtr = KMInteger.exp();
    short ptr = instance(TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), tagType);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), INVALID_TAG);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), intPtr);
    return ptr;
  }

  public static short instance(short tagType, short key) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short intPtr = KMInteger.exp();
    return instance(tagType, key, intPtr);
  }

  public static short instance(short tagType, short key, short intObj) {
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    if (heap[intObj] != INTEGER_TYPE) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = instance(TAG_TYPE, (short) 6);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE), tagType);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 2), key);
    Util.setShort(heap, (short) (ptr + TLV_HEADER_SIZE + 4), intObj);
    return ptr;
  }

  public static KMIntegerTag cast(short ptr) {
    if (heap[ptr] != TAG_TYPE) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    short tagType = Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE));
    if (!validateTagType(tagType)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getTagType() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_TAG_OFFSET] + TLV_HEADER_SIZE));
  }

  public short getKey() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_TAG_OFFSET] + TLV_HEADER_SIZE + 2));
  }

  public short getValue() {
    return Util.getShort(heap, (short) (instanceTable[KM_INTEGER_TAG_OFFSET] + TLV_HEADER_SIZE + 4));
  }

  public short length() {
    KMInteger obj = KMInteger.cast(getValue());
    return obj.length();
  }

  private static boolean validateKey(short key) {
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return true;
      }
    }
    return false;
  }

  private static boolean validateTagType(short tagType) {
    return (tagType == DATE_TAG) || (tagType == UINT_TAG) || (tagType == ULONG_TAG);
  }

  public static short getShortValue(short tagType, short tagKey, short keyParameters) {
    short ptr;
    if (tagType == UINT_TAG) {
      ptr = KMKeyParameters.findTag(KMType.UINT_TAG, tagKey, keyParameters);
      if (ptr != KMType.INVALID_VALUE) {
        ptr = KMIntegerTag.cast(ptr).getValue();
        if (KMInteger.cast(ptr).getSignificantShort() == 0) {
          return KMInteger.cast(ptr).getShort();
        }
      }
    }
    return KMType.INVALID_VALUE;
  }

  public static short getValue(
    byte[] buf, short offset, short tagType, short tagKey, short keyParameters) {
    short ptr;
    if ((tagType == UINT_TAG) || (tagType == ULONG_TAG) || (tagType == DATE_TAG)) {
      ptr = KMKeyParameters.findTag(tagType, tagKey, keyParameters);
      if (ptr != KMType.INVALID_VALUE) {
        ptr = KMIntegerTag.cast(ptr).getValue();
        return KMInteger.cast(ptr).value(buf, offset);
      }
    }
    return KMType.INVALID_VALUE;
  }

  public boolean isValidKeySize(byte alg) {
    short val = KMIntegerTag.cast(instanceTable[KM_INTEGER_TAG_OFFSET]).getValue();
    if (KMInteger.cast(val).getSignificantShort() != 0) {
      return false;
    }
    val = KMInteger.cast(val).getShort();
    switch (alg) {
      case KMType.RSA:
        if (val == 2048) {
          return true;
        }
        break;
      case KMType.AES:
        if (val == 128 || val == 256) {
          return true;
        }
        break;
      case KMType.DES:
        if (val == 192 || val == 168) {
          return true;
        }
        break;
      case KMType.EC:
        if (val == 256) {
          return true;
        }
        break;
      case KMType.HMAC:
        if (val % 8 == 0 && val >= 64 && val <= 512) {
          return true;
        }
        break;
      default:
        break;
    }
    return false;
  }
}
