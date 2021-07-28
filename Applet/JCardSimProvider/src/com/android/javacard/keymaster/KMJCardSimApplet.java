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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;

public class KMJCardSimApplet extends KMKeymasterApplet {
  // Provider specific Commands
  private static final byte INS_KEYMINT_PROVIDER_APDU_START = 0x00;
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 1;
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD = INS_KEYMINT_PROVIDER_APDU_START + 2;
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_KEYMINT_PROVIDER_APDU_START + 3;
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 4;
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_KEYMINT_PROVIDER_APDU_START + 5;
  private static final byte INS_KEYMINT_PROVIDER_APDU_END = 0x1F;

  private boolean locked;

  KMJCardSimApplet() {
    super(new KMJCardSimulator());
    locked = false;
    setDummyBootParams();
    setDummyPresharedKey();
    setDummyAttestationIds();
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
    // If this is select applet apdu which is selecting this applet then return
    if (apdu.isISOInterindustryCLA()) {
      if (selectingApplet()) {
        return;
      }
    }
    short apduIns = validateApdu(apdu);
    if(((KMJCardSimulator)seProvider).isPowerReset()){
      super.powerReset();
    }
    if (locked) {
      switch (apduIns) {
        case INS_SET_BOOT_PARAMS_CMD:
          processSetBootParamsCmd(apdu);
          break;
        default:
          super.process(apdu);
          break;
      }
      return;
    }
    if(apduIns == KMType.INVALID_VALUE) return;
    switch (apduIns) {
      case INS_PROVISION_ATTEST_IDS_CMD:
        processProvisionAttestIdsCmd(apdu);
        break;
      case INS_PROVISION_PRESHARED_SECRET_CMD:
        processProvisionPreSharedSecretCmd(apdu);
        break;
      case INS_GET_PROVISION_STATUS_CMD:
        processGetProvisionStatusCmd(apdu);
        break;
      case INS_LOCK_PROVISIONING_CMD:
        processLockProvisioningCmd(apdu);
        break;
      case INS_SET_BOOT_PARAMS_CMD:
        processSetBootParamsCmd(apdu);
        break;
      default:
        super.process(apdu);
        break;
    }
  }

  private void processProvisionAttestIdsCmd(APDU apdu) {

  }

  private void processProvisionPreSharedSecretCmd(APDU apdu) {
  }

  private void processGetProvisionStatusCmd(APDU apdu) {
  }

  private void processSetBootParamsCmd(APDU apdu) {
  }

  private void processLockProvisioningCmd(APDU apdu) {
    locked = true;
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

  private void setDummyBootParams(){
    short osVersion = KMInteger.uint_16(((short)0));
    short osPatchLevel = KMInteger.uint_16((short)0);
    short vendorPatchLevel = KMInteger.uint_16((short)0);
    short bootPatchLevel = KMInteger.uint_16((short) 0);

    super.setOsVersion(osVersion);
    super.setOsPatchLevel(osPatchLevel);
    super.setVendorPatchLevel(vendorPatchLevel);

    byte[] bootBlob = "00011122233344455566677788899900".getBytes();
    short bootKey = KMByteBlob.instance(bootBlob, (short) 0,
        (short) bootBlob.length);
    short verifiedHash = KMByteBlob.instance(bootBlob, (short) 0,
        (short) bootBlob.length);
    short bootState = KMType.VERIFIED_BOOT;

    ((KMJCardSimulator)seProvider).setBootPatchLevel(
        KMInteger.cast(bootPatchLevel).getBuffer(),
        KMInteger.cast(bootPatchLevel).getStartOff(),
        KMInteger.cast(bootPatchLevel).length());

    ((KMJCardSimulator)seProvider).setBootKey(
        KMByteBlob.cast(bootKey).getBuffer(),
        KMByteBlob.cast(bootKey).getStartOff(),
        KMByteBlob.cast(bootKey).length());

    ((KMJCardSimulator)seProvider).setVerifiedBootHash(
        KMByteBlob.cast(verifiedHash).getBuffer(),
        KMByteBlob.cast(verifiedHash).getStartOff(),
        KMByteBlob.cast(verifiedHash).length());

    ((KMJCardSimulator)seProvider).setBootState((byte)bootState);
    ((KMJCardSimulator)seProvider).setDeviceLocked(false);
    super.reboot();
  }

  private void setDummyPresharedKey(){
    final byte[] presharedKey = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    ((KMJCardSimulator)seProvider).createPresharedKey(presharedKey, (short)0, (short)presharedKey.length);
  }

  private void setDummyAttestationIds(){
    final byte[] dummy = {'D','U','M','M','Y'};
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_BRAND,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_IMEI,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_DEVICE,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_MEID,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_MODEL,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_MANUFACTURER,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_PRODUCT,dummy,(short)0,(short)dummy.length);
    ((KMJCardSimulator)seProvider).setAttestationId(KMType.ATTESTATION_ID_SERIAL,dummy,(short)0,(short)dummy.length);
  }

}
