/*
 * Copyright(C) 2022 The Android Open Source Project
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
package com.android.javacard.kmapplet;

import com.android.javacard.kmdevice.KMBootDataStore;

public class KMBootParamsProviderImpl implements KMBootDataStore {

  KMKeymintDataStore kmStoreDataInst;

  public KMBootParamsProviderImpl(KMKeymintDataStore storeData) {
    kmStoreDataInst = storeData;
  }

  @Override
  public short getVerifiedBootHash(byte[] buffer, short start) {
    return kmStoreDataInst.getVerifiedBootHash(buffer, start);
  }

  @Override
  public short getBootKey(byte[] buffer, short start) {
    return kmStoreDataInst.getBootKey(buffer, start);
  }

  @Override
  public short getBootState() {
    return kmStoreDataInst.getBootState();
  }

  @Override
  public boolean isDeviceBootLocked() {
    return kmStoreDataInst.isDeviceBootLocked();
  }

  @Override
  public short getBootPatchLevel(byte[] buffer, short start) {
    return kmStoreDataInst.getBootPatchLevel(buffer, start);
  }

}
