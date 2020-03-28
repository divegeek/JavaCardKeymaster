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

public class KMEnumArrayTag extends KMTag {

  // Arrays given below, together they form multi dimensional array.
  // Tag
  private static short[] tags = {PURPOSE, BLOCK_MODE, DIGEST, PADDING};
  // Tag Values.
  private static Object[] enums = null;
  // Tag Key
  private short key;
  // Byte Array of Tag Values.
  private KMByteBlob array;

  // assignBlob constructor
  private KMEnumArrayTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    array = null;
  }

  @Override
  public short getKey() {
    return key;
  }

  @Override
  public short getTagType() {
    return KMType.ENUM_ARRAY_TAG;
  }
  // returns the length
  @Override
  public short length() {
    return array.length();
  }

  public static KMEnumArrayTag instance() {
    return repository.newEnumArrayTag();
  }

  public static void create(KMEnumArrayTag[] enumArrayTagRefTable) {
    if (enums == null) {
      enums =
          new Object[] {
            new byte[] {ENCRYPT, DECRYPT, SIGN, VERIFY, WRAP_KEY, ATTEST_KEY},
            new byte[] {ECB, CBC, CTR},
            new byte[] {DIGEST_NONE, MD5, SHA1, SHA2_224, SHA2_256, SHA2_384, SHA2_512},
            new byte[] {
              PADDING_NONE, RSA_OAEP, RSA_PSS, RSA_PKCS1_1_5_ENCRYPT, RSA_PKCS1_1_5_SIGN, PKCS7
            }
          };
    }
    byte index = 0;
    while (index < enumArrayTagRefTable.length) {
      enumArrayTagRefTable[index] = new KMEnumArrayTag();
      index++;
    }
  }

  // create default assignBlob without any value array
  public static KMEnumArrayTag instance(short key) {
    // check if key is valid.
    byte[] vals = getAllowedEnumValues(key);
    if (vals == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    KMEnumArrayTag tag = repository.newEnumArrayTag();
    tag.key = key;
    tag.array = null;
    return tag;
  }

  // Set the expected length for the prototype.
  public KMEnumArrayTag withLength(short length) {
    array.withLength(length);
    return this;
  }

  // get the allowed enum values for given tag key
  private static byte[] getAllowedEnumValues(short key) {
    // check if key is allowed
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return (byte[]) enums[index];
      }
    }
    return null;
  }

  // get value array of this tag assignBlob.
  public KMByteBlob getValues() {
    return this.array;
  }

  public KMEnumArrayTag setValues(KMByteBlob val) {
    this.array = val;
    return this;
  }
  // instantiate enum array pointing to existing array.
  public static KMEnumArrayTag instance(short key, KMByteBlob blob) {
    // validate key
    byte[] allowedVals = getAllowedEnumValues(key);
    if (allowedVals == null) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    short byteIndex = 0;
    while (byteIndex < blob.length()) {
      short enumIndex = 0;
      boolean validValue = false;
      while (enumIndex < allowedVals.length) {
        if (blob.get(byteIndex) == allowedVals[enumIndex]) {
          validValue = true;
          break;
        }
        enumIndex++;
      }
      if (!validValue) {
        ISOException.throwIt(ISO7816.SW_DATA_INVALID);
      }
      byteIndex++;
    }
    KMEnumArrayTag tag = repository.newEnumArrayTag();
    tag.key = key;
    tag.array = blob;
    return tag;
  }
}
