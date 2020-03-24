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

public class KMIntegerArrayTag extends KMTag {
  private static final short[] tags = {USER_SECURE_ID};
  private short key;
  private KMVector vals;
  private short tagType;

  private KMIntegerArrayTag() {
    init();
  }

  @Override
  public void init() {
    key = 0;
    vals = null;
    tagType = KMType.UINT_ARRAY_TAG;
  }

  @Override
  public short getKey() {
    return key;
  }

  @Override
  public short length() {
    return this.vals.length();
  }

  @Override
  public short getTagType() {
    return tagType;
  }

  public static KMIntegerArrayTag instance() {
    return repository.newIntegerArrayTag();
  }

  public static void create(KMIntegerArrayTag[] intArrayTagRefTable) {
    byte index = 0;
    while (index < intArrayTagRefTable.length) {
      intArrayTagRefTable[index] = new KMIntegerArrayTag();
      index++;
    }
  }

  public KMIntegerArrayTag asUlongArray() {
    tagType = KMType.ULONG_ARRAY_TAG;
    return this;
  }

  public static KMIntegerArrayTag instance(short key) {
    if (!validateKey(key)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    KMIntegerArrayTag tag = repository.newIntegerArrayTag();
    tag.key = key;
    tag.vals = KMVector.instance(KMInteger.instance());
    return tag;
  }

  public static KMIntegerArrayTag instance(short key, KMVector val) {
    if (!(val.getType() instanceof KMInteger)) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    if (!(validateKey(key))) {
      throw new KMException(ISO7816.SW_DATA_INVALID);
    }
    KMIntegerArrayTag tag = repository.newIntegerArrayTag();
    tag.key = key;
    tag.vals = val;
    return tag;
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

  public KMIntegerArrayTag withLength(short length) {
    this.vals.withLength(length);
    return this;
  }

  public KMVector getValues() {
    return this.vals;
  }

  public KMIntegerArrayTag setValues(KMVector vals) {
    this.vals = vals;
    return this;
  }

  public void add(short index, KMInteger val) {
    this.vals.add(index, val);
  }

  public KMInteger get(short index) {
    return (KMInteger) this.vals.get(index);
  }
}
