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

import com.android.javacard.seprovider.KMDeviceUniqueKey;
import com.android.javacard.seprovider.KMException;
import com.android.javacard.seprovider.KMJCardSimulator;
import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

public class KMJCardSimApplet extends KMKeymasterApplet {

  // Provider specific Commands
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 1;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 2;
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 4;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 5;
  private static final byte INS_PROVISION_DEVICE_UNIQUE_KEY_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 6;
  private static final byte INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD =
      INS_KEYMINT_PROVIDER_APDU_START + 7;
  private static final byte INS_KEYMINT_PROVIDER_APDU_END = 0x1F;

  //Provision reporting status
  private static final byte NOT_PROVISIONED = 0x00;
  private static final byte PROVISION_STATUS_ATTESTATION_KEY = 0x01;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04;
  private static final byte PROVISION_STATUS_ATTEST_IDS = 0x08;
  private static final byte PROVISION_STATUS_PRESHARED_SECRET = 0x10;
  private static final byte PROVISION_STATUS_BOOT_PARAM = 0x20;
  private static final byte PROVISION_STATUS_PROVISIONING_LOCKED = 0x40;
  private static final byte PROVISION_STATUS_DEVICE_UNIQUE_KEY = 0x60;
  private static final byte PROVISION_STATUS_ADDITIONAL_CERT_CHAIN = (byte) 0x80;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;
  public static final short SHARED_SECRET_KEY_SIZE = 32;
  public static final byte BOOT_KEY_MAX_SIZE = 32;
  public static final byte BOOT_HASH_MAX_SIZE = 32;

  private static byte provisionStatus = NOT_PROVISIONED;

  KMJCardSimApplet() {
    super(new KMJCardSimulator());
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    new KMJCardSimApplet().register();
  }

  @Override
  public void process(APDU apdu) {
    try {
      // If this is select applet apdu which is selecting this applet then return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      short apduIns = validateApdu(apdu);
      if (((KMJCardSimulator) seProvider).isPowerReset()) {
        super.powerReset();
      }
      if (((KMJCardSimulator) seProvider).isProvisionLocked()) {
        switch (apduIns) {
          case INS_SET_BOOT_PARAMS_CMD:
            processSetBootParamsCmd(apdu);
            // set boot params event is propagated to KMKeymasterApplet to handle any
            // necessary cleanup after device reboot.
            super.process(apdu);
            break;
          default:
            super.process(apdu);
            break;
        }
        return;
      }
      if (apduIns == KMType.INVALID_VALUE) {
        return;
      }
      switch (apduIns) {
        case INS_PROVISION_ATTEST_IDS_CMD:
          processProvisionAttestIdsCmd(apdu);
          provisionStatus |= PROVISION_STATUS_ATTEST_IDS;
          sendError(apdu, KMError.OK);
          break;
        case INS_PROVISION_PRESHARED_SECRET_CMD:
          processProvisionPreSharedSecretCmd(apdu);
          provisionStatus |= PROVISION_STATUS_PRESHARED_SECRET;
          sendError(apdu, KMError.OK);
          break;
        case INS_GET_PROVISION_STATUS_CMD:
          processGetProvisionStatusCmd(apdu);
          break;
        case INS_LOCK_PROVISIONING_CMD:
          processLockProvisioningCmd(apdu);
          break;
        case INS_SET_BOOT_PARAMS_CMD:
          processSetBootParamsCmd(apdu);
          provisionStatus |= PROVISION_STATUS_BOOT_PARAM;
          break;
        case INS_PROVISION_DEVICE_UNIQUE_KEY_CMD:
          processProvisionDeviceUniqueKey(apdu);
          provisionStatus |= PROVISION_STATUS_DEVICE_UNIQUE_KEY;
          break;
        case INS_PROVISION_ADDITIONAL_CERT_CHAIN_CMD:
          processProvisionAdditionalCertChain(apdu);
          provisionStatus |= PROVISION_STATUS_ADDITIONAL_CERT_CHAIN;
          break;
        default:
          super.process(apdu);
          break;
      }
    } finally {
      repository.clean();
    }
  }

  private void processProvisionAttestIdsCmd(APDU apdu) {

    short keyparams = KMKeyParameters.exp();
    short cmd = KMArray.instance((short) 1);
    KMArray.cast(cmd).add((short) 0, keyparams);
    short args = receiveIncoming(apdu, cmd);
    short attData = KMArray.cast(args).get((short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    setAttestationIds(attData);
  }

  public void setAttestationIds(short attIdVals) {
    KMKeyParameters instParam = KMKeyParameters.cast(attIdVals);
    KMArray vals = KMArray.cast(instParam.getVals());
    short index = 0;
    short length = vals.length();
    short key;
    short type;
    short obj;
    while (index < length) {
      obj = vals.get(index);
      key = KMTag.getKey(obj);
      type = KMTag.getTagType(obj);

      if (KMType.BYTES_TAG != type) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      obj = KMByteTag.cast(obj).getValue();
      ((KMJCardSimulator) seProvider).setAttestationId(key, KMByteBlob.cast(obj).getBuffer(),
          KMByteBlob.cast(obj).getStartOff(), KMByteBlob.cast(obj).length());
      index++;
    }
  }

  private void processProvisionPreSharedSecretCmd(APDU apdu) {

    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, blob);
    short args = receiveIncoming(apdu, argsProto);

    short val = KMArray.cast(args).get((short) 0);

    if (val != KMType.INVALID_VALUE
        && KMByteBlob.cast(val).length() != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Persist shared Hmac.
    ((KMJCardSimulator) seProvider).createPresharedKey(
        KMByteBlob.cast(val).getBuffer(),
        KMByteBlob.cast(val).getStartOff(),
        KMByteBlob.cast(val).length());
  }

  private void processGetProvisionStatusCmd(APDU apdu) {
    short resp = KMArray.instance((short) 2);
    KMArray.cast(resp).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(resp).add((short) 1, KMInteger.uint_16(provisionStatus));
    sendOutgoing(apdu, resp);

  }

  private void processSetBootParamsCmd(APDU apdu) {
    short argsProto = KMArray.instance((short) 5);
    // Array of 4 expected arguments
    // Argument 0 Boot Patch level
    KMArray.cast(argsProto).add((short) 0, KMInteger.exp());
    // Argument 1 Verified Boot Key
    KMArray.cast(argsProto).add((short) 1, KMByteBlob.exp());
    // Argument 2 Verified Boot Hash
    KMArray.cast(argsProto).add((short) 2, KMByteBlob.exp());
    // Argument 3 Verified Boot State
    KMArray.cast(argsProto).add((short) 3, KMEnum.instance(KMType.VERIFIED_BOOT_STATE));
    // Argument 4 Device Locked
    KMArray.cast(argsProto).add((short) 4, KMEnum.instance(KMType.DEVICE_LOCKED));

    short args = receiveIncoming(apdu, argsProto);
    short bootParam = KMArray.cast(args).get((short) 0);

    ((KMJCardSimulator) seProvider).setBootPatchLevel(KMInteger.cast(bootParam).getBuffer(),
        KMInteger.cast(bootParam).getStartOff(),
        KMInteger.cast(bootParam).length());

    bootParam = KMArray.cast(args).get((short) 1);
    if (KMByteBlob.cast(bootParam).length() > BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMJCardSimulator) seProvider).setBootKey(KMByteBlob.cast(bootParam).getBuffer(),
        KMByteBlob.cast(bootParam).getStartOff(),
        KMByteBlob.cast(bootParam).length());

    bootParam = KMArray.cast(args).get((short) 2);
    if (KMByteBlob.cast(bootParam).length() > BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    ((KMJCardSimulator) seProvider).setVerifiedBootHash(KMByteBlob.cast(bootParam).getBuffer(),
        KMByteBlob.cast(bootParam).getStartOff(),
        KMByteBlob.cast(bootParam).length());

    bootParam = KMArray.cast(args).get((short) 3);
    byte enumVal = KMEnum.cast(bootParam).getVal();
    ((KMJCardSimulator) seProvider).setBootState(enumVal);

    bootParam = KMArray.cast(args).get((short) 4);
    enumVal = KMEnum.cast(bootParam).getVal();
    ((KMJCardSimulator) seProvider).setDeviceLocked(enumVal == KMType.DEVICE_LOCKED_TRUE);

    super.reboot();
    sendError(apdu, KMError.OK);
  }

  private void processLockProvisioningCmd(APDU apdu) {
    ((KMJCardSimulator) seProvider).setProvisionLocked(true);
    sendError(apdu, KMError.OK);
  }

  private short validateApdu(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      sendError(apdu, KMError.UNSUPPORTED_CLA);
      return KMType.INVALID_VALUE;
    }

    // Validate P1P2.
    if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      sendError(apdu, KMError.INVALID_P1P2);
      return KMType.INVALID_VALUE;
    }
    return apduBuffer[ISO7816.OFFSET_INS];
  }

  private void setDummyBootParams() {
    short osVersion = KMInteger.uint_16(((short) 0));
    short osPatchLevel = KMInteger.uint_16((short) 0);
    short vendorPatchLevel = KMInteger.uint_16((short) 0);
    short bootPatchLevel = KMInteger.uint_16((short) 0);

    super.setOsVersion(osVersion);
    super.setOsPatchLevel(osPatchLevel);
    super.setVendorPatchLevel(vendorPatchLevel);

    byte[] bootBlob = new byte[32];
    short bootKey = KMByteBlob.instance(bootBlob, (short) 0,
        (short) bootBlob.length);
    short verifiedHash = KMByteBlob.instance(bootBlob, (short) 0,
        (short) bootBlob.length);
    short bootState = KMType.UNVERIFIED_BOOT;

    ((KMJCardSimulator) seProvider).setBootPatchLevel(
        KMInteger.cast(bootPatchLevel).getBuffer(),
        KMInteger.cast(bootPatchLevel).getStartOff(),
        KMInteger.cast(bootPatchLevel).length());

    ((KMJCardSimulator) seProvider).setBootKey(
        KMByteBlob.cast(bootKey).getBuffer(),
        KMByteBlob.cast(bootKey).getStartOff(),
        KMByteBlob.cast(bootKey).length());

    ((KMJCardSimulator) seProvider).setVerifiedBootHash(
        KMByteBlob.cast(verifiedHash).getBuffer(),
        KMByteBlob.cast(verifiedHash).getStartOff(),
        KMByteBlob.cast(verifiedHash).length());

    ((KMJCardSimulator) seProvider).setBootState((byte) bootState);
    ((KMJCardSimulator) seProvider).setDeviceLocked(true);
    super.reboot();
  }

  private void setDummyPresharedKey() {
    final byte[] presharedKey = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    ((KMJCardSimulator) seProvider)
        .createPresharedKey(presharedKey, (short) 0, (short) presharedKey.length);
  }

  private void setDummyAttestationIds() {
    final byte[] brand = {'g', 'e', 'n', 'e', 'r', 'i', 'c'};
    final byte[] device = {'v', 's', 'o', 'c', '_', 'x', '8', '6', '_', '6', '4'};//vsoc_x86_64
    final byte[] product =  //aosp_cf_x86_64_phone
        {'a', 'o', 's', 'p', '_', 'c', 'f', '_', 'x', '8', '6', '_', '6', '4', '_', 'p', 'h', 'o',
            'n', 'e'};
    final byte[] serial = {};
    final byte[] imei = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
    final byte[] meid = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
    final byte[] manufacturer = {'G', 'o', 'o', 'g', 'l', 'e'};
    final byte[] model = //"Cuttlefish x86_64 phone"
        {'C', 'u', 't', 't', 'l', 'e', 'f', 'i', 's', 'h', ' ', 'x', '8', '6', '_', '6', '4',
            ' ', 'p', 'h', 'o', 'n', 'e'};
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_BRAND, brand, (short) 0, (short) brand.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_IMEI, imei, (short) 0, (short) imei.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_DEVICE, device, (short) 0, (short) device.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_MEID, meid, (short) 0, (short) meid.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_MODEL, model, (short) 0, (short) model.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_MANUFACTURER, manufacturer, (short) 0,
            (short) manufacturer.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_PRODUCT, product, (short) 0,
            (short) product.length);
    ((KMJCardSimulator) seProvider)
        .setAttestationId(KMType.ATTESTATION_ID_SERIAL, serial, (short) 0, (short) serial.length);
  }

  private static void processProvisionDeviceUniqueKey(APDU apdu) {
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    short arr = KMArray.instance((short) 1);
    short coseKeyExp = KMCoseKey.exp();
    KMArray.cast(arr).add((short) 0, coseKeyExp); //[ CoseKey ]
    arr = receiveIncoming(apdu, arr);
    // Get cose key.
    short coseKey = KMArray.cast(arr).get((short) 0);
    short pubKeyLen = KMCoseKey.cast(coseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
    short privKeyLen = KMCoseKey.cast(coseKey).getPrivateKey(scratchPad, pubKeyLen);
    //Store the Device unique Key.
    seProvider.createDeviceUniqueKey(false, scratchPad, (short) 0, pubKeyLen, scratchPad,
        pubKeyLen, privKeyLen);
    // Newly added code 30/07/2021
    short bcc = generateBcc(false, scratchPad);
    short len = KMKeymasterApplet.encodeToApduBuffer(bcc, scratchPad, (short) 0,
        MAX_COSE_BUF_SIZE);
    ((KMJCardSimulator) seProvider).persistBootCertificateChain(scratchPad, (short) 0, len);
    sendError(apdu, KMError.OK);
  }

  private static void processProvisionAdditionalCertChain(APDU apdu) {
    // Prepare the expression to decode
    short headers = KMCoseHeaders.exp();
    short arrInst = KMArray.instance((short) 4);
    KMArray.cast(arrInst).add((short) 0, KMByteBlob.exp());
    KMArray.cast(arrInst).add((short) 1, headers);
    KMArray.cast(arrInst).add((short) 2, KMByteBlob.exp());
    KMArray.cast(arrInst).add((short) 3, KMByteBlob.exp());
    short coseSignArr = KMArray.exp(arrInst);
    short map = KMMap.instance((short) 1);
    KMMap.cast(map).add((short) 0, KMTextString.exp(), coseSignArr);
    // TODO duplicate code.
    // receive incoming data and decode it.
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repository.allocReclaimableMemory(bufferLength);
    short index = bufferStartOffset;
    byte[] buffer = repository.getHeap();
    while (recvLen > 0 && ((short) (index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    // decode
    map = decoder.decode(map, buffer, bufferStartOffset, bufferLength);
    arrInst = KMMap.cast(map).getKeyValue((short) 0);
    // Validate Additional certificate chain.
    short leafCoseKey =
        validateCertChain(false, KMCose.COSE_ALG_ES256, KMCose.COSE_ALG_ES256, arrInst,
            srcBuffer, null);
    // Compare the DK_Pub.
    short pubKeyLen = KMCoseKey.cast(leafCoseKey).getEcdsa256PublicKey(srcBuffer, (short) 0);
    KMDeviceUniqueKey uniqueKey = seProvider.getDeviceUniqueKey(false);
    if (uniqueKey == null) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    short uniqueKeyLen = uniqueKey.getPublicKey(srcBuffer, pubKeyLen);
    if ((pubKeyLen != uniqueKeyLen) ||
        (0 != Util.arrayCompare(srcBuffer, (short) 0, srcBuffer, pubKeyLen, pubKeyLen))) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    seProvider.persistAdditionalCertChain(buffer, bufferStartOffset, bufferLength);
    //reclaim memory
    repository.reclaimMemory(bufferLength);
    sendError(apdu, KMError.OK);
  }

  private static short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (((KMJCardSimulator) seProvider).isPowerReset()) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        KMInteger.cast(int32Ptr).getStartOff(),
        powerResetStatus);

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        (short) (KMInteger.cast(int32Ptr).getStartOff() + 2),
        err);
    // reset power reset status flag to its default value.
    //repository.restorePowerResetStatus(); //TODO
    return int32Ptr;
  }

}
