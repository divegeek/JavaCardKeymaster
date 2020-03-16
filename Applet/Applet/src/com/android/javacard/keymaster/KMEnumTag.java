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

public class KMEnumTag extends KMTag {

  private static short[] tags = {
    ALGORITHM, ECCURVE, BLOB_USAGE_REQ, USER_AUTH_TYPE, ORIGIN, HARDWARE_TYPE
  };

  private static Object[] enums = null;

  private short key;
  private byte val;

  // assignBlob constructor
  private KMEnumTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    val = 0;
  }

  @Override
  public short getKey() {
    return key;
  }

  @Override
  public short length() {
    return 1;
  }

  @Override
  public short getTagType() {
    return KMType.ENUM_TAG;
  }

  public static KMEnumTag instance() {
    return repository.newEnumTag();
  }

  public static KMEnumTag instance(short key) {
    if (validateEnum(key, NO_VALUE)) {
      KMEnumTag tag = repository.newEnumTag();
      tag.key = key;
      return tag;
    } else {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
  }

  public static void create(KMEnumTag[] enumTagRefTable) {
    if (enums == null) {
      enums =
          new Object[] {
            new byte[] {RSA, DES, EC, AES, HMAC},
            new byte[] {P_224, P_256, P_384, P_521},
            new byte[] {STANDALONE, REQUIRES_FILE_SYSTEM},
            new byte[] {USER_AUTH_NONE, PASSWORD, FINGERPRINT, ANY},
            new byte[] {GENERATED, DERIVED, IMPORTED, UNKNOWN, SECURELY_IMPORTED},
            new byte[] {SOFTWARE, TRUSTED_ENVIRONMENT, STRONGBOX}
          };
    }
    byte index = 0;
    while (index < enumTagRefTable.length) {
      enumTagRefTable[index] = new KMEnumTag();
      index++;
    }
  }

  // validate enumeration keys and values.
  private static boolean validateEnum(short key, byte value) {
    // check if key exists
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        // check if value given
        if (value != NO_VALUE) {
          // check if the value exist
          byte[] vals = (byte[]) enums[index];
          short enumInd = (short) vals.length;
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

  // get value of this tag assignBlob.
  public byte getValue() {
    return val;
  }

  // instantiate enum tag.
  public static KMEnumTag instance(short key, byte val) {
    if (!validateEnum(key, val)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    KMEnumTag tag = instance(key);
    tag.val = val;
    return tag;
  }
}
