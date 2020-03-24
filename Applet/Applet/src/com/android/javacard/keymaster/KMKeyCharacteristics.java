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

public class KMKeyCharacteristics extends KMType {
  public static final byte SOFTWARE_ENFORCED = 0x00;
  public static final byte HARDWARE_ENFORCED = 0x01;
  private KMArray vals;

  private KMKeyCharacteristics() {
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

  public static KMKeyCharacteristics instance() {
    KMKeyCharacteristics inst = repository.newKeyCharacteristics();
    inst.vals = KMArray.instance((short) 2);
    inst.vals.add(SOFTWARE_ENFORCED, KMKeyParameters.instance());
    inst.vals.add(HARDWARE_ENFORCED, KMKeyParameters.instance());
    return inst;
  }

  public static KMKeyCharacteristics instance(KMArray vals) {
    if (vals.length() != 2) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    KMKeyCharacteristics inst = repository.newKeyCharacteristics();
    inst.vals = vals;
    return inst;
  }

  public static void create(KMKeyCharacteristics[] keyCharRefTable) {
    byte index = 0;
    while (index < keyCharRefTable.length) {
      keyCharRefTable[index] = new KMKeyCharacteristics();
      index++;
    }
  }

  public KMKeyParameters getSoftwareEnforced() {
    return (KMKeyParameters) vals.get(SOFTWARE_ENFORCED);
  }

  public KMKeyParameters getHardwareEnforced() {
    return (KMKeyParameters) vals.get(HARDWARE_ENFORCED);
  }

  public KMArray getVals() {
    return vals;
  }
}
