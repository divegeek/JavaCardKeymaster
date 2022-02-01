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
package com.android.javacard.kmdevice;

public interface KMBootDataStore {

  /**
   * Get Verified Boot hash. Part of RoT. Part of data sent by the aosp bootloader.
   */
  short getVerifiedBootHash(byte[] buffer, short start);

  /**
   * Get Boot Key. Part of RoT. Part of data sent by the aosp bootloader.
   */
  short getBootKey(byte[] buffer, short start);

  /**
   * Get Boot state. Part of RoT. Part of data sent by the aosp bootloader.
   */
  short getBootState();

  /**
   * Returns true if device bootloader is locked. Part of RoT. Part of data sent by the aosp
   * bootloader.
   */
  boolean isDeviceBootLocked();

  /**
   * Get Boot patch level. Part of data sent by the aosp bootloader.
   */
  short getBootPatchLevel(byte[] buffer, short start);
}
