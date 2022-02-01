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

import org.globalplatform.upgrade.Element;

import com.android.javacard.kmdevice.KMArray;
import com.android.javacard.kmdevice.KMInteger;
import com.android.javacard.kmdevice.KMKeyParameters;
import com.android.javacard.kmdevice.KMKeymasterDevice;
import com.android.javacard.kmdevice.KMRepository;
import com.android.javacard.kmdevice.KMSEProvider;
import com.android.javacard.kmdevice.KMDataStoreConstants;
import com.android.javacard.kmdevice.KMTag;
import com.android.javacard.kmdevice.KMByteBlob;
import com.android.javacard.kmdevice.KMByteTag;
import com.android.javacard.kmdevice.KMDataStore;
import com.android.javacard.kmdevice.KMDecoder;
import com.android.javacard.kmdevice.KMEnum;
import com.android.javacard.kmdevice.KMEnumArrayTag;
import com.android.javacard.kmdevice.KMEnumTag;
import com.android.javacard.kmdevice.KMException;

import javacard.framework.APDU;
import javacard.framework.Util;

public class KMKeymasterProvision {

  //Provision reporting status
  private static final byte NOT_PROVISIONED = 0x00;
  private static final byte PROVISION_STATUS_ATTESTATION_KEY = 0x01;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04;
  private static final byte PROVISION_STATUS_ATTEST_IDS = 0x08;
  private static final byte PROVISION_STATUS_PRESHARED_SECRET = 0x10;
  private static final byte PROVISION_STATUS_PROVISIONING_LOCKED = 0x20;

  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;

  public static final short SHARED_SECRET_KEY_SIZE = 32;
  //protected static byte provisionStatus = NOT_PROVISIONED;

  protected KMKeymasterDevice kmDeviceInst;
  protected KMSEProvider seProvider;
  protected KMDecoder kmDecoder;
  protected KMRepository kmRepositroyInst;
  protected KMDataStore kmStoreDataInst;

  public KMKeymasterProvision(KMKeymasterDevice deviceInst, KMSEProvider provider,
      KMDecoder decoder, KMRepository repoInst,
      KMDataStore storeData) {
    kmDeviceInst = deviceInst;
    seProvider = provider;
    kmDecoder = decoder;
    kmRepositroyInst = repoInst;
    kmStoreDataInst = storeData;
    if (!seProvider.isUpgrading()) {
      writeProvisionStatus(NOT_PROVISIONED);
    }
  }

  protected void writeProvisionStatus(byte provisionStatus) {
    short offset = kmRepositroyInst.alloc((short) 1);
    byte[] buffer = kmRepositroyInst.getHeap();
    buffer[offset] = 0;
    short len = kmStoreDataInst.getData(KMDataStoreConstants.PROVISIONED_STATUS, buffer, offset);
    buffer[offset] |= provisionStatus;
    kmStoreDataInst.storeData(KMDataStoreConstants.PROVISIONED_STATUS,
        buffer, offset, (short) 1);
  }

  private byte getProvisionStatus(byte[] buffer, short offset) {
    short len = kmStoreDataInst.getData(KMDataStoreConstants.PROVISIONED_STATUS, buffer, offset);
    if (len == 0) {
      return NOT_PROVISIONED;
    }
    return buffer[offset];
  }

  public void processProvisionAttestationKey(APDU apdu) {
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.add(argsProto, (short) 0, keyparams);
    KMArray.add(argsProto, (short) 1, keyFormatPtr);
    KMArray.add(argsProto, (short) 2, blob);

    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();

    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);

    // key params should have os patch, os version and verified root of trust
    short keyParams = KMArray.get(args, (short) 0);
    keyFormatPtr = KMArray.get(args, (short) 1);
    short rawBlob = KMArray.get(args, (short) 2);
    // Key format must be RAW format
    short keyFormat = KMEnum.getVal(keyFormatPtr);
    if (keyFormat != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    //byte origin = KMType.IMPORTED;

    // get algorithm - only EC keys expected
    KMTag.assertPresence(keyParams, KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, keyParams);
    if (alg != KMType.EC) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get digest - only SHA256 supported
    KMTag.assertPresence(keyParams, KMType.ENUM_ARRAY_TAG, KMType.DIGEST, KMError.INVALID_ARGUMENT);
    short len = KMEnumArrayTag.getValues(KMType.DIGEST, keyParams, scratchPad, (short) 0);
    if (len != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (scratchPad[0] != KMType.SHA2_256) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    // Purpose should be ATTEST_KEY
    KMTag.assertPresence(keyParams, KMType.ENUM_ARRAY_TAG, KMType.PURPOSE,
        KMError.INVALID_ARGUMENT);
    len = KMEnumArrayTag.getValues(KMType.PURPOSE, keyParams, scratchPad, (short) 0);
    if (len != 1) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (scratchPad[0] != KMType.ATTEST_KEY) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    // validate Curve
    KMTag.assertPresence(keyParams, KMType.ENUM_TAG, KMType.ECCURVE, KMError.INVALID_ARGUMENT);
    short curve = KMEnumTag.getValue(KMType.ECCURVE, keyParams);
    if (curve != KMType.P_256) {
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }
    // Decode EC Key
    short arrPtr = kmDeviceInst.decodeRawECKey(rawBlob);
    short secret = KMArray.get(arrPtr, (short) 0);
    short pubKey = KMArray.get(arrPtr, (short) 1);
    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.EC,
        KMByteBlob.getBuffer(secret),
        KMByteBlob.getStartOff(secret),
        KMByteBlob.length(secret),
        KMByteBlob.getBuffer(pubKey),
        KMByteBlob.getStartOff(pubKey),
        KMByteBlob.length(pubKey));

    // persist key
    kmStoreDataInst.storeData(KMDataStoreConstants.ATTESTATION_KEY,
        KMByteBlob.getBuffer(secret),
        KMByteBlob.getStartOff(secret),
        KMByteBlob.length(secret));

    writeProvisionStatus(PROVISION_STATUS_ATTESTATION_KEY);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processProvisionAttestationCertDataCmd(APDU apdu) {
    // Buffer holds the corresponding offsets and lengths of the certChain, certIssuer and certExpiry
    // in the bufferRef[0] buffer.
    short var = KMByteBlob.instance((short) 12);
    // These variables point to the appropriate positions in the var buffer.
    short certChainPos = KMByteBlob.getStartOff(var);
    short certIssuerPos = (short) (KMByteBlob.getStartOff(var) + 4);
    short certExpiryPos = (short) (KMByteBlob.getStartOff(var) + 8);
    short recvLen = apdu.setIncomingAndReceive();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = kmRepositroyInst.allocReclaimableMemory(bufferLength);
    byte[] buffer = kmRepositroyInst.getHeap();
    kmDeviceInst.receiveIncomingCertData(apdu, buffer, bufferLength,
        bufferStartOffset, recvLen, KMByteBlob.getBuffer(var), KMByteBlob.getStartOff(var));
    // persist data
    kmStoreDataInst.persistCertificateData(
        (byte[]) buffer,
        Util.getShort(KMByteBlob.getBuffer(var), certChainPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certChainPos + 2)), // length
        Util.getShort(KMByteBlob.getBuffer(var), certIssuerPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certIssuerPos + 2)), // length
        Util.getShort(KMByteBlob.getBuffer(var), certExpiryPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certExpiryPos + 2))); // length

    // reclaim memory
    kmRepositroyInst.reclaimMemory(bufferLength);
    writeProvisionStatus((byte) (PROVISION_STATUS_ATTESTATION_CERT_CHAIN |
        PROVISION_STATUS_ATTESTATION_CERT_PARAMS));
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processProvisionAttestIdsCmd(APDU apdu) {
    short keyparams = KMKeyParameters.exp();
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, keyparams);
    short args = kmDeviceInst.receiveIncoming(apdu, cmd);

    short attData = KMArray.get(args, (short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    setAttestationIds(attData);
    writeProvisionStatus(PROVISION_STATUS_ATTEST_IDS);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processProvisionPreSharedSecretCmd(APDU apdu) {
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.add(argsProto, (short) 0, blob);
    short args = kmDeviceInst.receiveIncoming(apdu, argsProto);

    short val = KMArray.get(args, (short) 0);

    if (val != KMType.INVALID_VALUE
        && KMByteBlob.length(val) != SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Persist shared Hmac.
    kmStoreDataInst.storeData(KMDataStoreConstants.PRE_SHARED_KEY,
        KMByteBlob.getBuffer(val),
        KMByteBlob.getStartOff(val),
        KMByteBlob.length(val));
    writeProvisionStatus(PROVISION_STATUS_PRESHARED_SECRET);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processGetProvisionStatusCmd(APDU apdu) {
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, kmDeviceInst.buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1,
        KMInteger.uint_16(getProvisionStatus(apdu.getBuffer(), (short) 0)));
    kmDeviceInst.sendOutgoing(apdu, resp);
  }

  public void processLockProvisioningCmd(APDU apdu) {
    byte[] buffer = apdu.getBuffer();
    buffer[0] = 0x01;
    kmStoreDataInst.storeData(KMDataStoreConstants.PROVISIONED_LOCKED, buffer, (short) 0,
        (short) 1);
    writeProvisionStatus(PROVISION_STATUS_PROVISIONING_LOCKED);
    kmDeviceInst.sendError(apdu, KMError.OK);
  }

  public void processProvisionDeviceUniqueKey(APDU apdu) {
    kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);
  }

  public void processProvisionAdditionalCertChain(APDU apdu) {
    kmDeviceInst.sendError(apdu, KMError.CMD_NOT_ALLOWED);
  }

  public short mapAttestIdToStoreId(short tag) {
    switch (tag) {
      // Attestation Id Brand
      case KMType.ATTESTATION_ID_BRAND:
        return KMDataStoreConstants.ATT_ID_BRAND;
      // Attestation Id Device
      case KMType.ATTESTATION_ID_DEVICE:
        return KMDataStoreConstants.ATT_ID_DEVICE;
      // Attestation Id Product
      case KMType.ATTESTATION_ID_PRODUCT:
        return KMDataStoreConstants.ATT_ID_PRODUCT;
      // Attestation Id Serial
      case KMType.ATTESTATION_ID_SERIAL:
        return KMDataStoreConstants.ATT_ID_SERIAL;
      // Attestation Id IMEI
      case KMType.ATTESTATION_ID_IMEI:
        return KMDataStoreConstants.ATT_ID_IMEI;
      // Attestation Id MEID
      case KMType.ATTESTATION_ID_MEID:
        return KMDataStoreConstants.ATT_ID_MEID;
      // Attestation Id Manufacturer
      case KMType.ATTESTATION_ID_MANUFACTURER:
        return KMDataStoreConstants.ATT_ID_MANUFACTURER;
      // Attestation Id Model
      case KMType.ATTESTATION_ID_MODEL:
        return KMDataStoreConstants.ATT_ID_MODEL;
      default:
        KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    return KMType.INVALID_VALUE;
  }

  protected void setAttestationIds(short attIdVals) {
    short vals = KMKeyParameters.getVals(attIdVals);
    short index = 0;
    short length = KMArray.length(vals);
    short key;
    short type;
    short obj;
    while (index < length) {
      obj = KMArray.get(vals, index);
      key = KMTag.getKMTagKey(obj);
      type = KMTag.getKMTagType(obj);

      if (KMType.BYTES_TAG != type) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      obj = KMByteTag.getValue(obj);
      kmStoreDataInst.storeData((byte) mapAttestIdToStoreId(key), KMByteBlob.getBuffer(obj),
          KMByteBlob.getStartOff(obj), KMByteBlob.length(obj));
      index++;
    }
  }

  //This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  public short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (((KMAndroidSEProvider) seProvider).isPowerReset(true)) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        KMInteger.getStartOff(int32Ptr),
        powerResetStatus);

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        (short) (KMInteger.getStartOff(int32Ptr) + 2),
        err);
    // reset power reset status flag to its default value.
    //repository.restorePowerResetStatus(); //TODO
    return int32Ptr;
  }

}
