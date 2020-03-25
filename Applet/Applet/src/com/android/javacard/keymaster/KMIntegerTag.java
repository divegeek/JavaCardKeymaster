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

// Implements UINT, ULONG and DATE tags.
public class KMIntegerTag extends KMTag {
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

  private short key;
  private KMInteger val;
  private short tagType;

  private KMIntegerTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    val = null;
    tagType = KMType.UINT_TAG;
  }

  @Override
  public short getKey() {
    return key;
  }

  @Override
  public short length() {
    return (short) val.getValue().length;
  }

  @Override
  public short getTagType() {
    return tagType;
  }

  public static KMIntegerTag instance() {
    return repository.newIntegerTag();
  }

  public static KMIntegerTag instance(short key) {
    if (!validateKey(key)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    KMIntegerTag tag = repository.newIntegerTag();
    tag.key = key;
    tag.val = null;
    return tag;
  }

  public static KMIntegerTag instance(short givenKey, KMInteger val) {
    KMIntegerTag tag = KMIntegerTag.instance(givenKey);
    tag.val = val;
    if (val.length() == 8) {
      tag.tagType = KMType.ULONG_TAG;
    }
    return tag;
  }

  public static void create(KMIntegerTag[] intTagRefTable) {
    byte index = 0;
    while (index < intTagRefTable.length) {
      intTagRefTable[index] = new KMIntegerTag();
      index++;
    }
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

  public KMInteger getValue() {
    return this.val;
  }

  public KMIntegerTag setValue(KMInteger val) {
    this.val = val;
    return this;
  }

  public KMIntegerTag asULong() {
    tagType = KMType.ULONG_TAG;
    return this;
  }

  public KMIntegerTag asDate() {
    tagType = KMType.DATE_TAG;
    return this;
  }
}
