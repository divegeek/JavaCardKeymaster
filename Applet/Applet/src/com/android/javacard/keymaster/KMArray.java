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

public class KMArray extends KMType {
  private KMType[] vals;
  private short length;
  private short startOff;

  private KMArray() {
    init();
  }

  @Override
  public void init() {
    vals = null;
    startOff = 0;
    length = 0;
  }

  @Override
  public short length() {
    return length;
  }

  public static void create(KMArray[] arrayRefTable) {
    byte index = 0;
    while (index < arrayRefTable.length) {
      arrayRefTable[index] = new KMArray();
      index++;
    }
  }

  public static KMArray instance() {
    return repository.newArray();
  }

  public static KMArray instance(short length) {

    KMArray inst = repository.newArray();
    inst.startOff = repository.newTypeArray(length);
    inst.vals = repository.getTypeArrayRef();
    inst.length = length;
    return inst;
  }

  public KMArray withLength(short length) {
    this.length = length;
    return this;
  }

  public KMArray add(short index, KMType val) {
    if (index >= length) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    vals[(short) (startOff + index)] = val;
    return this;
  }

  public KMType get(short index) {
    if (index >= length) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    return vals[(short) (startOff + index)];
  }
}
