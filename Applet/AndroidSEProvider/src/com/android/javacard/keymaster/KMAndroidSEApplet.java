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
 * distributed under the License is distributed on an "AS IS" (short)0IS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.javacard.keymaster;

import org.globalplatform.upgrade.Element;
import org.globalplatform.upgrade.OnUpgradeListener;
import org.globalplatform.upgrade.UpgradeManager;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;

public class KMAndroidSEApplet extends KMKeymasterApplet implements OnUpgradeListener {

  KMAndroidSEApplet() {
    super(new KMAndroidSEProvider());
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMAndroidSEApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
  }

  @Override
  public void onCleanup() {
  }

  @Override
  public void onConsolidate() {
  }

  @Override
  public void onRestore(Element element) {
    element.initRead();
    byte firstByte = element.readByte();
    short oldPackageVersion = 0;
    if (firstByte == KMKeymasterApplet.KM_MAGIC_NUMBER) {
      oldPackageVersion = element.readShort();
      provisionStatus = element.readByte();
    } else {
      // MAGIC_NUMBER is introduced in version 2.0. Upgrade is
      // not allowed for Applets having version less than 2.0
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    if (!isUpgradeAllowed(oldPackageVersion)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    keymasterState = element.readByte();
    repository.onRestore(element, oldPackageVersion, KM_APPLET_PACKAGE_VERSION);
    seProvider.onRestore(element, oldPackageVersion, KM_APPLET_PACKAGE_VERSION);
    handleDataUpgrade();
  }

  @Override
  public Element onSave() {
    // SEProvider count
    short primitiveCount = seProvider.getBackupPrimitiveByteCount();
    short objectCount = seProvider.getBackupObjectCount();
    //Repository count
    primitiveCount += repository.getBackupPrimitiveByteCount();
    objectCount += repository.getBackupObjectCount();
    //KMKeymasterApplet count
    primitiveCount += computePrimitveDataSize();
    objectCount += computeObjectCount();

    // Create element.
    Element element = UpgradeManager.createElement(Element.TYPE_SIMPLE,
        primitiveCount, objectCount);
    element.write(KM_MAGIC_NUMBER);
    element.write(packageVersion);
    element.write(provisionStatus);
    element.write(keymasterState);
    repository.onSave(element);
    seProvider.onSave(element);
    return element;
  }

  private short computePrimitveDataSize() {
    // provisionStatus + keymasterState + magic byte + version
    return (short) 5;
  }

  private short computeObjectCount() {
    return (short) 0;
  }

  public boolean isUpgradeAllowed(short oldVersion) {
    boolean upgradeAllowed = false;
    short oldMajorVersion = (short) ((oldVersion >> 8) & 0x00FF);
    short oldMinorVersion = (short) (oldVersion & 0x00FF);
    short currentMajorVersion = (short) (KM_APPLET_PACKAGE_VERSION >> 8 & 0x00FF);
    short currentMinorVersion = (short) (KM_APPLET_PACKAGE_VERSION & 0x00FF);
    // Downgrade of the Applet is not allowed.
    // Upgrade is not allowed to a next version which is not immediate.
    if ((short) (currentMajorVersion - oldMajorVersion) == 1) {
      if (currentMinorVersion == 0) {
        upgradeAllowed = true;
      }
    } else if ((short) (currentMajorVersion - oldMajorVersion) == 0) {
      if (currentMinorVersion >= oldMinorVersion) {
        upgradeAllowed = true;
      }
    }
    return upgradeAllowed;
  }
  
  public void handleDataUpgrade() {
    // In version 3.0, two new provisionStatus states are introduced
    // 1. PROVISION_STATUS_SE_LOCKED - bit 6 of provisionStatus
    // 2. PROVISION_STATUS_OEM_PUBLIC_KEY - bit 7 of provisionStatus
    // In the process of upgrade from 2.0 to 3.0 OEM PUBLIC Key is provisioned
    // in SEProvider.so update the state of the provision status by making
    // 7th bit HIGH.
    provisionStatus |= PROVISION_STATUS_OEM_ROOT_PUBLIC_KEY;
    // Check if the provisioning is already locked. If so update
    // the state of the provisionStatus by making 6th bit HIGH.
    // Lock the SE Factory provisioning as well.
    if ( 0 != (provisionStatus & PROVISION_STATUS_OEM_PROVISIONING_LOCKED)) {
      provisionStatus |= PROVISION_STATUS_SE_FACTORY_PROVISIONING_LOCKED;
    }
  }
}

