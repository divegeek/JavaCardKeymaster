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

public class KMBoolTag extends KMTag {

  private static final short[] tags = {
    CALLER_NONCE,
    INCLUDE_UNIQUE_ID,
    BOOTLOADER_ONLY,
    ROLLBACK_RESISTANCE,
    NO_AUTH_REQUIRED,
    ALLOW_WHILE_ON_BODY,
    TRUSTED_USER_PRESENCE_REQUIRED,
    TRUSTED_CONFIRMATION_REQUIRED,
    UNLOCKED_DEVICE_REQUIRED,
    RESET_SINCE_ID_ROTATION
  };

  // Array of Tag Values.
  private short key;
  private byte val;

  // assignBlob constructor
  private KMBoolTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    val = 1; // always 1.
  }

  public static KMBoolTag instance() {
    return repository.newBoolTag();
  }

  public static void create(KMBoolTag[] boolTagRefTable) {
    byte index = 0;
    while (index < boolTagRefTable.length) {
      boolTagRefTable[index] = new KMBoolTag();
      index++;
    }
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
    return KMType.BOOL_TAG;
  }

  public byte getVal() {
    return val;
  }
  // create default assignBlob without any value
  public static KMBoolTag instance(short key) {
    if (!validateKey(key)) {
      ISOException.throwIt(ISO7816.SW_DATA_INVALID);
    }
    KMBoolTag tag = repository.newBoolTag();
    tag.key = key;
    return tag;
  }

  // validate the tag key
  private static boolean validateKey(short key) {
    short index = (short) tags.length;
    while (--index >= 0) {
      if (tags[index] == key) {
        return true;
      }
    }
    return false;
  }
}
