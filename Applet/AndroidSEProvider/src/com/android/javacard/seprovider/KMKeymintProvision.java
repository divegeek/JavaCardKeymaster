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
package com.android.javacard.seprovider;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMCose;
import com.android.javacard.kmdevice.KMCoseHeaders;
import com.android.javacard.kmdevice.KMCoseKey;
import com.android.javacard.kmdevice.KMDataStore;
import com.android.javacard.kmdevice.KMDataStoreConstants;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMDeviceUniqueKey;
import com.android.javacard.kmdevice.KMException;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMKeymintDevice;
import com.android.javacard.kmdevice.KMMap;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMRkpDataStore;
import com.android.javacard.kmdevice.KMSEProvider;
import com.android.javacard.kmdevice.KMTextString;
import com.android.javacard.kmdevice.RemotelyProvisionedComponentDevice;

import javacard.framework.APDU;
import javacard.framework.Util;

public class KMKeymintProvision extends KMKeymasterProvision {

  private static final byte PROVISION_STATUS_DEVICE_UNIQUE_KEY = 0x40;
  private static final byte PROVISION_STATUS_ADDITIONAL_CERT_CHAIN = (byte) 0x80;
  private KMRkpDataStore rkpDataStore;

  public KMKeymintProvision(KMKeymasterDevice deviceInst, KMSEProvider provider,
      KMDecoder decoder, KMRepository repoInst, KMDataStore storeData, KMRkpDataStore rkpStore) {
    super(deviceInst, provider, decoder, repoInst, storeData);
    rkpDataStore = rkpStore;
  }

  @Override
  public void processProvisionAttestationKey(APDU apdu) {
    kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);
  }

  @Override
  public void processProvisionAttestationCertDataCmd(APDU apdu) {
    kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);
  }

  @Override
  public void processProvisionDeviceUniqueKey(APDU apdu) {
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short arr = KMArray.instance((short) 1);
    short coseKeyExp = KMCoseKey.exp();
    KMArray.add(arr, (short) 0, coseKeyExp); //[ CoseKey ]
    arr = kmDeviceInst.receiveIncoming(apdu, arr);
    // Get cose key.
    short coseKey = KMArray.get(arr, (short) 0);
    short pubKeyLen = KMCoseKey.cast(coseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
    short privKeyLen = KMCoseKey.cast(coseKey).getPrivateKey(scratchPad, pubKeyLen);
    //Store the Device unique Key.
    rkpDataStore.createDeviceUniqueKey(false, scratchPad, (short) 0, pubKeyLen, scratchPad,
        pubKeyLen, privKeyLen);
    short bcc = ((KMKeymintDevice) kmDeviceInst).generateBcc(false, scratchPad);
    short len = kmDeviceInst.encodeToApduBuffer(bcc, scratchPad, (short) 0,
        RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);
    rkpDataStore.storeData(KMDataStoreConstants.BOOT_CERT_CHAIN, scratchPad, (short) 0, len);
    writeProvisionStatus(PROVISION_STATUS_DEVICE_UNIQUE_KEY);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  @Override
  public void processProvisionAdditionalCertChain(APDU apdu) {
    // Prepare the expression to decode
    short headers = KMCoseHeaders.exp();
    short arrInst = KMArray.instance((short) 4);
    KMArray.add(arrInst, (short) 0, KMByteBlob.exp());
    KMArray.add(arrInst, (short) 1, headers);
    KMArray.add(arrInst, (short) 2, KMByteBlob.exp());
    KMArray.add(arrInst, (short) 3, KMByteBlob.exp());
    short coseSignArr = KMArray.exp(arrInst);
    short map = KMMap.instance((short) 1);
    KMMap.add(map, (short) 0, KMTextString.exp(), coseSignArr);
    // receive incoming data and decode it.
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = kmRepositroyInst.allocReclaimableMemory(bufferLength);
    byte[] buffer = kmRepositroyInst.getHeap();
    map = kmDeviceInst.receiveIncoming(apdu, map, buffer, bufferLength, bufferStartOffset, recvLen);
    arrInst = KMMap.getKeyValue(map, (short) 0);
    // Validate Additional certificate chain.
    short leafCoseKey =
        ((KMKeymintDevice) kmDeviceInst).validateCertChain(false, KMCose.COSE_ALG_ES256,
            KMCose.COSE_ALG_ES256, arrInst,
            srcBuffer, null);
    // Compare the DK_Pub.
    short pubKeyLen = KMCoseKey.cast(leafCoseKey).getEcdsa256PublicKey(srcBuffer, (short) 0);
    KMDeviceUniqueKey uniqueKey = rkpDataStore.getDeviceUniqueKey(false);
    if (uniqueKey == null) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    short uniqueKeyLen = uniqueKey.getPublicKey(srcBuffer, pubKeyLen);
    if ((pubKeyLen != uniqueKeyLen) ||
        (0 != Util.arrayCompare(srcBuffer, (short) 0, srcBuffer, pubKeyLen, pubKeyLen))) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    rkpDataStore.storeData(KMDataStoreConstants.ADDITIONAL_CERT_CHAIN, buffer, bufferStartOffset,
        bufferLength);
    //reclaim memory
    kmRepositroyInst.reclaimMemory(bufferLength);
    writeProvisionStatus(PROVISION_STATUS_ADDITIONAL_CERT_CHAIN);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  @Override
  public short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 2);

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        (short) (KMInteger.getStartOff(int32Ptr)),
        err);

    return int32Ptr;
  }

}
