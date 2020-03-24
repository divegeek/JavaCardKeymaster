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

public class KMGetHWInfoCmd extends KMAbstractCmd {
  public static final byte INS_GET_HW_INFO_CMD = 0x1E;
  public static final byte[] JavacardKeymasterDevice = {
    0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65,
    0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  public static final byte[] Google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

  @Override
  protected KMArray getExpectedArgs() {
    return null;
  }

  @Override
  protected KMArray process(KMArray args, KMContext context) {
    return KMArray.instance((short) 3)
        .add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX))
        .add(
            (short) 1,
            KMByteBlob.instance(
                JavacardKeymasterDevice, (short) 0, (short) JavacardKeymasterDevice.length))
        .add((short) 2, KMByteBlob.instance(Google, (short) 0, (short) Google.length));
  }

  @Override
  public byte getIns() {
    return INS_GET_HW_INFO_CMD;
  }

  @Override
  public boolean hasArguments() {
    return false;
  }
}
