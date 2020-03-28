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

// TODO complete the class design and implementation
public class KMOperationState {
  private KMInteger operationHandle;

  private KMOperationState() {
    operationHandle = null;
  }
/*
  public static KMOperationState instance(KMContext context) {
    // TODO make operation handle
    return context.getRepository().newOperationState();
  }
*/
  public static void create(KMOperationState[] opStateRefTable) {
    byte index = 0;
    while (index < opStateRefTable.length) {
      opStateRefTable[index] = new KMOperationState();
      index++;
    }
  }

  public KMInteger getOperationHandle() {
    return operationHandle;
  }

  public void setOperationHandle(KMInteger operationHandle) {
    this.operationHandle = operationHandle;
  }
/*
  public void release(KMContext context) {
    // TODO release handle
    context.getRepository().releaseOperationState(this);
  }

 */
}
