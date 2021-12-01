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
import javacard.framework.JCSystem;
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
    byte[] packageVersion_ = null;
    byte provisionStatus_ = firstByte;
    if (firstByte == KMKeymasterApplet.KM_MAGIC_NUMBER) {
      packageVersion_ = (byte[]) element.readObject();
      provisionStatus_ = element.readByte();
    }
    if (null != packageVersion_ && !isUpgradeAllowed(packageVersion_)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    JCSystem.beginTransaction();
    packageVersion = packageVersion_;
    provisionStatus = provisionStatus_;
    keymasterState = element.readByte();
    JCSystem.commitTransaction();
    repository.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
    seProvider.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
    handleDataUpgradeToVersion1_1();
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
    // provisionStatus + keymasterState + magic byte
    return (short) 3;
  }

  private short computeObjectCount() {
    return (short) 1;
  }
  
  public boolean isUpgradeAllowed(byte[] version) {
    boolean upgradeAllowed = false;
    short oldMajorVersion = Util.getShort(version, (short) 0);
    short oldMinorVersion = Util.getShort(version, (short) 2);
    short currentMajorVersion = Util.getShort(CURRENT_PACKAGE_VERSION, (short) 0);
    short currentMinorVersion = Util.getShort(CURRENT_PACKAGE_VERSION, (short) 2);
    // Downgrade of the Applet is not allowed.
    // Upgrade is not allowed to a next version which is not immediate.
    if (currentMajorVersion - oldMajorVersion == 1) {
      if (currentMinorVersion == 0) {
        upgradeAllowed = true;
      }
    } else if (currentMajorVersion - oldMajorVersion == 0) {
      if (currentMinorVersion - oldMinorVersion == 1) {
        upgradeAllowed = true;
      }
    }
    return upgradeAllowed;
  }
  
  public void handleDataUpgradeToVersion1_1() {
    
    if (packageVersion != null) {
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
    byte[] version = new byte[4];

    JCSystem.beginTransaction();
    packageVersion = version;
    provisionStatus = status;
    // Copy the package version.
    Util.arrayCopyNonAtomic(
        CURRENT_PACKAGE_VERSION,
        (short) 0,
        packageVersion,
        (short) 0,
        (short) CURRENT_PACKAGE_VERSION.length);
    JCSystem.commitTransaction();

    // Update computed HMAC key.
    short blob = repository.getComputedHmacKey();
    if (blob != KMType.INVALID_VALUE) {
      seProvider.createComputedHmacKey(
          KMByteBlob.cast(blob).getBuffer(),
          KMByteBlob.cast(blob).getStartOff(),
          KMByteBlob.cast(blob).length()
          );
    }
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
    repository.reclaimMemory((short) (certExpiryLen + issuerLen + certChainLen));
  }
}

