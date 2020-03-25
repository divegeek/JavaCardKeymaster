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

public class KMVector extends KMType {
  private KMType type;
  private KMArray vals;

  private KMVector() {
    init();
  }

  @Override
  public void init() {
    vals = null;
    type = null;
  }

  @Override
  public short length() {
    return vals.length();
  }

  public static KMVector instance(KMType type) {
    KMVector inst = repository.newVector();
    inst.type = type;
    inst.vals = KMArray.instance();
    return inst;
  }

  public static KMVector instance(KMType type, short length) {
    KMVector inst = repository.newVector();
    inst.type = type;
    inst.vals = KMArray.instance(length);
    return inst;
  }

  public static void create(KMVector[] vectorRefTable) {
    byte index = 0;
    while (index < vectorRefTable.length) {
      vectorRefTable[index] = new KMVector();
      index++;
    }
  }

  public KMArray getVals() {
    return vals;
  }

  public KMVector withLength(short length) {
    this.vals.withLength(length);
    return this;
  }

  public KMVector add(short index, KMType val) {
    vals.add(index, val);
    return this;
  }

  public KMType get(short index) {
    return vals.get(index);
  }

  public void setVals(KMArray vals) {
    this.vals = vals;
  }

  public KMType getType() {
    return type;
  }
}
