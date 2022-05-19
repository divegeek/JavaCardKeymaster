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
import javacard.framework.Util;

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
    short packageVersion_ = 0;
    byte provisionStatus_ = firstByte;
    if (firstByte == KMKeymasterApplet.KM_MAGIC_NUMBER) {
      packageVersion_ = element.readShort();
      provisionStatus_ = element.readByte();
    }
    if (0 != packageVersion_ && !isUpgradeAllowed(packageVersion_)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    packageVersion = packageVersion_;
    provisionStatus = provisionStatus_;
    keymasterState = element.readByte();
    repository.onRestore(element, packageVersion, KM_PERSISTENT_DATA_STORAGE_VERSION);
    seProvider.onRestore(element, packageVersion, KM_PERSISTENT_DATA_STORAGE_VERSION);
    handleDataUpgradeToVersion2_0();
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

  public boolean isUpgradeAllowed(short version) {
    boolean upgradeAllowed = false;
    short oldMajorVersion = (short) ((version >> 8) & 0x00FF);
    short oldMinorVersion = (short) (version & 0x00FF);
    short currentMajorVersion = (short) (KM_PERSISTENT_DATA_STORAGE_VERSION >> 8 & 0x00FF);
    short currentMinorVersion = (short) (KM_PERSISTENT_DATA_STORAGE_VERSION & 0x00FF);
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

  public void handleDataUpgradeToVersion2_0() {
    
    if (packageVersion != 0) {
      // No Data upgrade required.
      return;
    }
    byte status = provisionStatus;
    // In the current version of the applet set boot parameters is removed from
    // provision status so readjust the provision locked flag.
    // 0x40 is provision locked flag in the older applet.
    // Unset the 5th bit. setboot parameters flag.
    status = (byte)  (status & 0xDF);
    // Readjust the lock provisioned status flag.
    if ((status & 0x40) == 0x40) {
      // 0x40 to 0x20
      // Unset 6th bit
      status = (byte) (status & 0xBF);
      // set the 5th bit
      status = (byte) (status | 0x20);
    }
    provisionStatus = status;
    packageVersion = KM_PERSISTENT_DATA_STORAGE_VERSION;

    short certExpiryLen = 0;
    short issuerLen = 0;
    short certExpiry = repository.getCertExpiryTime();
    if (certExpiry != KMType.INVALID_VALUE) {
      certExpiryLen = KMByteBlob.cast(certExpiry).length();
    }
    short issuer = repository.getIssuer();
    if (issuer != KMType.INVALID_VALUE) {
      issuerLen = KMByteBlob.cast(issuer).length();
    }
    short certChainLen = seProvider.getProvisionedDataLength(KMSEProvider.CERTIFICATE_CHAIN);
    short offset = repository.allocReclaimableMemory((short) (certExpiryLen + issuerLen + certChainLen));
    // Get the start offset of the certificate chain.
    short certChaionOff =
        decoder.getCborBytesStartOffset(
            repository.getHeap(),
            offset,
            seProvider.readProvisionedData(KMSEProvider.CERTIFICATE_CHAIN, repository.getHeap(), offset));
    certChainLen -= (short) (certChaionOff - offset);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(issuer).getBuffer(),
        KMByteBlob.cast(issuer).getStartOff(),
        repository.getHeap(),
        (short) (certChaionOff + certChainLen),
        issuerLen);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(certExpiry).getBuffer(),
        KMByteBlob.cast(certExpiry).getStartOff(),
        repository.getHeap(),
        (short) (certChaionOff + certChainLen + issuerLen),
        certExpiryLen);

    seProvider.persistProvisionData(
        repository.getHeap(),
        certChaionOff, // cert chain offset
        certChainLen,
        (short) (certChaionOff + certChainLen), // issuer offset
        issuerLen,
        (short) (certChaionOff + certChainLen + issuerLen), // cert expiry offset
        certExpiryLen);

    // Update computed HMAC key.
    short blob = repository.getComputedHmacKey();
    if (blob != KMType.INVALID_VALUE) {
      seProvider.createComputedHmacKey(
          KMByteBlob.cast(blob).getBuffer(),
          KMByteBlob.cast(blob).getStartOff(),
          KMByteBlob.cast(blob).length()
          );
    } else {
      // Initialize the Key object.
      Util.arrayFillNonAtomic(repository.getHeap(), offset, (short) 32, (byte) 0);
      seProvider.createComputedHmacKey(repository.getHeap(), offset,(short) 32);
    }
    repository.reclaimMemory((short) (certExpiryLen + issuerLen + certChainLen));
  }
}

