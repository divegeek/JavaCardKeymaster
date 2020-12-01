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
 * KMEnumTag represents ENUM Tag type specified in android keymaster hal specifications.
 * struct{byte TAG_TYPE; short length; struct{short ENUM_TAG; short tagKey; byte value}}
 */

public class KMEnumTag extends KMTag {
  private static KMEnumTag prototype;
  private static short instPtr;


  // The allowed tag keys of type enum tag.
  private static short[] tags = {
    ALGORITHM, ECCURVE, BLOB_USAGE_REQ, USER_AUTH_TYPE, ORIGIN, HARDWARE_TYPE
  };

  private static Object[] enums = null;

  private KMEnumTag() {}

  private static KMEnumTag proto(short ptr) {
    if (prototype == null) prototype = new KMEnumTag();
    instPtr = ptr;
    return prototype;
  }

  // pointer to an empty instance used as expression
  public static short exp() {
    short ptr = instance(TAG_TYPE, (short)2);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), ENUM_TAG);
    return ptr;
  }

  public static short instance(short key) {
    if(!validateEnum(key, NO_VALUE)){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = KMType.instance(TAG_TYPE, (short)4);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), ENUM_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), key);
    return ptr;
  }

  public static short instance(short key, byte val) {
    if(!validateEnum(key, val)){
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short ptr = instance(TAG_TYPE, (short)5);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE), ENUM_TAG);
    Util.setShort(heap, (short)(ptr+TLV_HEADER_SIZE+2), key);
    heap[(short)(ptr+TLV_HEADER_SIZE+4)]= val;
    return ptr;
  }

  public static KMEnumTag cast(short ptr) {
    if (heap[ptr] != TAG_TYPE) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    if (Util.getShort(heap, (short) (ptr + TLV_HEADER_SIZE)) != ENUM_TAG) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    return proto(ptr);
  }

  public short getKey() {
    return Util.getShort(heap, (short)(instPtr+TLV_HEADER_SIZE+2));
  }

  public short getTagType() {
    return KMType.ENUM_TAG;
  }

  public byte getValue() {
    return heap[(short)(instPtr+TLV_HEADER_SIZE+4)];
  }

  public static void create() {
    if (enums == null) {
      // enum tag values.
      enums =
          new Object[] {
            new byte[] {RSA, DES, EC, AES, HMAC},
            new byte[] {P_224, P_256, P_384, P_521},
            new byte[] {STANDALONE, REQUIRES_FILE_SYSTEM},
            new byte[] {USER_AUTH_NONE, PASSWORD, FINGERPRINT, (byte)(PASSWORD & FINGERPRINT),ANY},
            new byte[] {GENERATED, DERIVED, IMPORTED, UNKNOWN, SECURELY_IMPORTED},
            new byte[] {SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX}
          };
    }
  }

  // isValidTag enumeration keys and values.
  private static boolean validateEnum(short key, byte value) {
    create();
    byte[] vals;
    short enumInd;
    // check if key exists
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        // check if value given
        if (value != NO_VALUE) {
          // check if the value exist
          vals = (byte[]) enums[index];
          enumInd = (short) vals.length;
          while (--enumInd >= 0) {
            if (vals[enumInd] == value) {
              // return true if value exist
              return true;
            }
          }
          // return false if value does not exist
          return false;
        }
        // return true if key exist and value not given
        return true;
      }
    }
    // return false if key does not exist
    return false;
  }

  public static short getValue(short tagType, short keyParameters){
    short tagPtr = KMKeyParameters.findTag(KMType.ENUM_TAG, tagType, keyParameters);
    if(tagPtr != KMType.INVALID_VALUE){
      return heap[(short)(tagPtr+TLV_HEADER_SIZE+4)];
    }
    return KMType.INVALID_VALUE;
  }
}
