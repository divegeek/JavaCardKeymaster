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

public class KMKeyParameters extends KMType {
  private KMArray vals;

  private KMKeyParameters() {
    init();
  }

  @Override
  public void init() {
    vals = null;
  }

  @Override
  public short length() {
    return vals.length();
  }

  public static KMKeyParameters instance() {
    KMKeyParameters inst = repository.newKeyParameters();
    inst.vals = KMArray.instance((short) 9);
    inst.vals.add((short) 0, KMIntegerTag.instance());
    inst.vals.add((short) 1, KMIntegerArrayTag.instance());
    inst.vals.add((short) 2, KMIntegerTag.instance().asULong());
    inst.vals.add((short) 3, KMIntegerTag.instance().asDate());
    inst.vals.add((short) 4, KMIntegerArrayTag.instance().asUlongArray());
    inst.vals.add((short) 5, KMEnumTag.instance());
    inst.vals.add((short) 6, KMEnumArrayTag.instance());
    inst.vals.add((short) 7, KMByteTag.instance());
    inst.vals.add((short) 8, KMBoolTag.instance());
    return inst;
  }

  public static KMKeyParameters instance(KMArray vals) {
    KMKeyParameters inst = repository.newKeyParameters();
    inst.vals = vals;
    return inst;
  }

  public static void create(KMKeyParameters[] keyParametersRefTable) {
    byte index = 0;
    while (index < keyParametersRefTable.length) {
      keyParametersRefTable[index] = new KMKeyParameters();
      index++;
    }
  }

  public KMArray getVals() {
    return vals;
  }
}
