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

public class KMProvisionCmd extends KMAbstractCmd {
  public static final byte INS_PROVISION_CMD = 0x23;

  @Override
  public byte getIns() {
    return INS_PROVISION_CMD;
  }

  @Override
  public KMArray process(KMArray args, KMContext context) {
    KMKeyParameters arg1 = (KMKeyParameters)args.get((short)0);
    KMEnum arg2 = (KMEnum)args.get((short)1);
    KMByteBlob arg3 = (KMByteBlob)args.get((short)2);
    provision(arg1, arg2.getVal(),arg3);
    context.setKeymasterState(KMKeymasterApplet.ACTIVE_STATE);
    //nothing to return
    return null;
  }

  // TODO implement functionality
  private void provision(KMKeyParameters params, byte keyFormat, KMByteBlob keyBlob){
  }

  @Override
  protected boolean validateState(byte state) {
    return (KMKeymasterApplet.FIRST_SELECT_STATE == state);
  }

  // Uses import key command signature but does not return anything back.
  protected KMArray getExpectedArgs() {
    // Argument 1
    KMKeyParameters keyparams = KMKeyParameters.instance();
    // Argument 2
    KMEnum keyFormat = KMEnum.instance().setType(KMType.KEY_FORMAT);
    // Argument 3
    KMByteBlob keyBlob = KMByteBlob.instance();
    // Array of expected arguments
    return KMArray.instance((short) 3)
        .add((short) 0, keyparams)
        .add((short) 1, keyFormat)
        .add((short) 2, keyBlob);
  }
}
