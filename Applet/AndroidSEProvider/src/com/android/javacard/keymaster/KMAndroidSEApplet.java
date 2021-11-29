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
    byte magicNumber = element.readByte();
    if (magicNumber != KMKeymasterApplet.KM_MAGIC_NUMBER) {
      // Previous version of the applet does not have versioning support.
      // In this case the first byte is the provision status.
      provisionStatus = magicNumber;
      keymasterState = element.readByte();
      repository.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
      seProvider.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
      handleDataUpgradeToVersion1_1();
    } else {
      byte[] version = (byte[]) element.readObject();
      if (!isUpgradeAllowed(version)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      packageVersion = version;
      provisionStatus = element.readByte();
      keymasterState = element.readByte();
      repository.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
      seProvider.onRestore(element, packageVersion, CURRENT_PACKAGE_VERSION);
    }
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
    short oldMajorVersion = Util.getShort(version, (short) 0);
    short oldMinorVersion = Util.getShort(version, (short) 2);
    short currentMajorVersion = Util.getShort(CURRENT_PACKAGE_VERSION, (short) 0);
    short currentMinorVersion = Util.getShort(CURRENT_PACKAGE_VERSION, (short) 2);
    // Downgrade of the Applet is not allowed.
    if (oldMajorVersion > currentMajorVersion ||
        (oldMajorVersion == currentMajorVersion && oldMinorVersion > currentMinorVersion)) {
      return false;
    }
    // Upgrade is not allowed to a next version which is not immediate.
    if (1 < (currentMajorVersion - oldMajorVersion) ||
        (oldMajorVersion == currentMajorVersion && 1 < (currentMinorVersion - oldMinorVersion)) ||
        (oldMajorVersion < currentMajorVersion && 0 != currentMinorVersion)) {
      return false;
    }
    return true;
  }
  
  public void handleDataUpgradeToVersion1_1() {
    
    // Copy the package version.
    Util.arrayCopy(
        CURRENT_PACKAGE_VERSION,
        (short) 0,
        packageVersion,
        (short) 0,
        (short) CURRENT_PACKAGE_VERSION.length);

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

