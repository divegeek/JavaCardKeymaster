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
    provisionStatus = element.readByte();
    keymasterState = element.readByte();
    // TODO write a comment
    if (dataBaseVersion <= CURRENT_DATABASE_VERSION) {
      dataBaseVersion = element.readShort();
    }
    repository.onRestore(element, dataBaseVersion, CURRENT_DATABASE_VERSION);
    seProvider.onRestore(element, dataBaseVersion, CURRENT_DATABASE_VERSION);
    if (dataBaseVersion == INVALID_DATA_VERSION) {
      handleDataUpgradeToVersion1();
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
    element.write(provisionStatus);
    element.write(keymasterState);
    element.write(dataBaseVersion);
    repository.onSave(element);
    seProvider.onSave(element);
    return element;
  }

  private short computePrimitveDataSize() {
    // provisionStatus + keymasterState
    return (short) 4;
  }

  private short computeObjectCount() {
    return (short) 0;
  }
  
  public void handleDataUpgradeToVersion1() {
    dataBaseVersion = CURRENT_DATABASE_VERSION;
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

