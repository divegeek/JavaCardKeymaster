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

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.CryptoException;

public class KMKeymintDevice extends KMKeymasterDevice {

  public static byte[] JAVACARD_KEYMINT_DEVICE;
  private static byte[] GOOGLE;
  private static byte[] dec319999Ms;
  private static byte[] dec319999;
  private static byte[] jan01970;
  private KMCose kmCoseInst;
  private RemotelyProvisionedComponentDevice rkp;
  private KMRkpDataStore rkpDataStoreInst;

  public KMKeymintDevice(KMSEProvider seImpl, KMRepository repoInst, KMEncoder encoderInst,
      KMDecoder decoderInst, KMDataStore storeData,
      KMBootDataStore bootParamsProvider, KMRkpDataStore rkpStore) {
    super(seImpl, repoInst, encoderInst, decoderInst, storeData, bootParamsProvider);
    rkpDataStoreInst = rkpStore;
    rkp = new RemotelyProvisionedComponentDevice(this, encoderInst, decoderInst, repoInst,
        seProvider, storeData, rkpStore, bootParamsProvider);
    kmCoseInst = KMCose.getInstance();
    initStatics();
  }

  public static void initStatics() {
    JAVACARD_KEYMINT_DEVICE = new byte[]{0x4a, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4b, 0x65,
        0x79, 0x6d, 0x69,
        0x6e, 0x74, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,};
    GOOGLE = new byte[]{0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
    dec319999Ms = new byte[]{(byte) 0, (byte) 0, (byte) 0xE6, (byte) 0x77, (byte) 0xD2, (byte) 0x1F,
        (byte) 0xD8,
        (byte) 0x18};
    dec319999 = new byte[]{0x39, 0x39, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39,
        0x35, 0x39,
        0x5a,};
    jan01970 = new byte[]{0x37, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30,
        0x5a,};
  }

  public void process(APDU apdu) {
    try {
      resetData();
      repository.onProcess();
      byte[] apduBuffer = apdu.getBuffer();
      byte apduIns = apduBuffer[ISO7816.OFFSET_INS];

      switch (apduIns) {
        case INS_GENERATE_RKP_KEY_CMD:
        case INS_BEGIN_SEND_DATA_CMD:
        case INS_UPDATE_CHALLENGE_CMD:
        case INS_UPDATE_EEK_CHAIN_CMD:
        case INS_UPDATE_KEY_CMD:
        case INS_FINISH_SEND_DATA_CMD:
        case INS_GET_RESPONSE_CMD:
        case INS_GET_RKP_HARDWARE_INFO:
          rkp.process(apduIns, apdu);
          break;
        default:
          super.process(apdu);
      }
    } catch (KMException exception) {
      sendError(apdu, KMException.reason());
    } catch (ISOException exp) {
      sendError(apdu, mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      sendError(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      repository.clean();
    }
  }

  @Override
  public short getHardwareInfo() {
    final byte version = 1;
    // Make the response
    short respPtr = KMArray.instance((short) 6);
    KMArray.add(respPtr, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(respPtr, (short) 1, KMInteger.uint_8(version));
    KMArray.add(respPtr, (short) 2, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    KMArray.add(respPtr, (short) 3,
        KMByteBlob.instance(JAVACARD_KEYMINT_DEVICE, (short) 0,
            (short) JAVACARD_KEYMINT_DEVICE.length));
    KMArray.add(respPtr, (short) 4, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    KMArray.add(respPtr, (short) 5, KMInteger.uint_8((byte) 1));
    return respPtr;
  }

  @Override
  public short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch,
      short vendorPatch,
      short bootPatch, short origin, byte[] scratchPad) {
    short strongboxParams = KMKeyParameters.makeSbEnforced(keyParams, (byte) origin, osVersion,
        osPatch, vendorPatch,
        bootPatch, scratchPad);
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams, scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams, scratchPad);
    // short emptyParam = KMArray.instance((short) 0);
    short keyCharacteristics = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.setStrongboxEnforced(keyCharacteristics, strongboxParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyCharacteristics, swParams);
    KMKeyCharacteristics.setTeeEnforced(keyCharacteristics, teeParams);
    return keyCharacteristics;
  }

  @Override
  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance();
    short emptyParam = KMArray.instance((short) 0);
    emptyParam = KMKeyParameters.instance(emptyParam);
    KMKeyCharacteristics.setStrongboxEnforced(keyChars, sbParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyChars, emptyParam);
    KMKeyCharacteristics.setTeeEnforced(keyChars, teeParams);
    return keyChars;
  }

  @Override
  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.exp();
  }

  @Override
  public short getHardwareParamters(short sbParams, short teeParams) {
    return KMKeyParameters.makeHwEnforced(sbParams, teeParams);
  }

  @Override
  public short concatParamsForAuthData(short keyBlobPtr, short hwParams, short swParams,
      short hiddenParams,
      short pubKey) {
    short arrayLen = 2;
    if (pubKey != KMType.INVALID_VALUE) {
      arrayLen = 3;
    }
    short params = KMArray.instance((short) arrayLen);
    KMArray.add(params, (short) 0, KMKeyParameters.getVals(hwParams));
    KMArray.add(params, (short) 1, KMKeyParameters.getVals(hiddenParams));
    if (3 == arrayLen) {
      KMArray.add(params, (short) 2, pubKey);
    }
    return params;
  }

  @Override
  public short getSupportedAttestationMode(short attChallenge) {
    // Attestation challenge present then it is an error because no factory
    // provisioned attest key
    short mode = KMType.NO_CERT; // TODO check what should be the default value
    if (attChallenge != KMType.INVALID_VALUE && KMByteBlob.length(attChallenge) > 0) {
      KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
    }
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.ATTEST_KEY, data[HW_PARAMETERS])
        || KMEnumArrayTag.contains(KMType.PURPOSE, KMType.SIGN, data[HW_PARAMETERS])) {
      mode = KMType.SELF_SIGNED_CERT;
    } else {
      mode = KMType.FAKE_CERT;
    }
    return mode;
  }

  @Override
  public KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad,
      KMSEProvider seProvider) {
    short alg = KMKeyParameters.findTag(keyParams, KMType.ENUM_TAG, KMType.ALGORITHM);
    boolean rsaCert = KMEnumTag.getValue(alg) == KMType.RSA;
    KMAttestationCert cert = KMAttestationCertImpl.instance(rsaCert, seProvider);

    // Validity period must be specified
    short notBefore = KMKeyParameters.findTag(keyParams, KMType.DATE_TAG,
        KMType.CERTIFICATE_NOT_BEFORE);
    if (notBefore == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_NOT_BEFORE);
    }
    notBefore = KMIntegerTag.getValue(notBefore);
    short notAfter = KMKeyParameters.findTag(keyParams, KMType.DATE_TAG,
        KMType.CERTIFICATE_NOT_AFTER);
    if (notAfter == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_NOT_AFTER);
    }
    notAfter = KMIntegerTag.getValue(notAfter);
    // VTS sends notBefore == Epoch.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
    short epoch = KMInteger.instance(scratchPad, (short) 0, (short) 8);
    short end = KMInteger.instance(dec319999Ms, (short) 0, (short) dec319999Ms.length);
    if (KMInteger.compare(notBefore, epoch) == 0) {
      cert.notBefore(KMByteBlob.instance(jan01970, (short) 0, (short) jan01970.length), true,
          scratchPad);
    } else {
      cert.notBefore(notBefore, false, scratchPad);
    }
    // VTS sends notAfter == Dec 31st 9999
    if (KMInteger.compare(notAfter, end) == 0) {
      cert.notAfter(KMByteBlob.instance(dec319999, (short) 0, (short) dec319999.length), true,
          scratchPad);
    } else {
      cert.notAfter(notAfter, false, scratchPad);
    }
    // Serial number
    short serialNum = KMKeyParameters.findTag(keyParams, KMType.BIGNUM_TAG,
        KMType.CERTIFICATE_SERIAL_NUM);
    if (serialNum != KMType.INVALID_VALUE) {
      serialNum = KMBignumTag.getValue(serialNum);
    } else {
      serialNum = KMByteBlob.instance((short) 1);
      KMByteBlob.add(serialNum, (short) 0, (byte) 1);
    }
    cert.serialNumber(serialNum);
    return cert;
  }

  @Override
  public short getMgf1Digest(short keyParams, short hwParams) {
    short mgfDigest = KMKeyParameters.findTag(keyParams, KMType.ENUM_ARRAY_TAG,
        KMType.RSA_OAEP_MGF_DIGEST);
    if (mgfDigest != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(mgfDigest) != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      mgfDigest = KMEnumArrayTag.get(mgfDigest, (short) 0);
      if (mgfDigest == KMType.DIGEST_NONE) {
        KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
      }
      if (!KMEnumArrayTag.contains(KMType.RSA_OAEP_MGF_DIGEST, mgfDigest, hwParams)) {
        KMException.throwIt(KMError.INCOMPATIBLE_MGF_DIGEST);
      }
      if (mgfDigest != KMType.SHA1 && mgfDigest != KMType.SHA2_256) {
        KMException.throwIt(KMError.UNSUPPORTED_MGF_DIGEST);
      }
    }
    return mgfDigest;
  }

  @Override
  public void beginKeyAgreementOperation(KMOperationState op) {
    if (op.getAlgorithm() != KMType.EC) {
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }

    op.setOperation(
        seProvider.initAsymmetricOperation((byte) op.getPurpose(), (byte) op.getAlgorithm(),
            (byte) op.getPadding(), (byte) op.getDigest(), KMType.DIGEST_NONE, /* No MGF1 Digest */
            KMByteBlob.getBuffer(data[SECRET]), KMByteBlob.getStartOff(data[SECRET]),
            KMByteBlob.length(data[SECRET]), null,
            (short) 0, (short) 0));
  }

  @Override
  public void finishKeyAgreementOperation(KMOperationState op, byte[] scratchPad) {
    try {
      KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
      short blob = pkcs8.decodeEcSubjectPublicKeyInfo(data[INPUT_DATA]);
      short len = op.getOperation().finish(KMByteBlob.getBuffer(blob), KMByteBlob.getStartOff(blob),
          KMByteBlob.length(blob), scratchPad, (short) 0);
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 32);
      Util.arrayCopyNonAtomic(scratchPad, (short) 0, KMByteBlob.getBuffer(data[OUTPUT_DATA]),
          KMByteBlob.getStartOff(data[OUTPUT_DATA]), len);
    } catch (CryptoException e) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  @Override
  public short getConfirmationToken(short confToken, short keyParams) {
    if (0 == KMByteBlob.length(confToken)) {
      KMException.throwIt(KMError.NO_USER_CONFIRMATION);
    }
    return confToken;
  }

  @Override
  public short getKMVerificationTokenExp() {
    return KMVerificationToken.timeStampTokenExp();
  }

  @Override
  public short getMacFromVerificationToken(short verToken) {
    return KMVerificationToken.getMac(verToken, (short) 0x02);
  }

  @Override
  public void validateECKeys() {
    // Read key size
    short eccurve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (eccurve == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else {
      if (eccurve != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
  }

  @Override
  public short buildErrorStatus(short err) {
    return KMInteger.uint_16(err);
  }

  @Override
  public short generateAttestKeyExp() {
    short params = KMKeyParameters.expAny();
    short blob = KMByteBlob.exp();
    // Array of expected arguments
    short cmd = KMArray.instance((short) 5);
    KMArray.add(cmd, (short) 0, blob); // key blob
    KMArray.add(cmd, (short) 1, params); // keyparamters to be attested.
    KMArray.add(cmd, (short) 2, blob); // attest key blob
    KMArray.add(cmd, (short) 3, params); // attest key params
    KMArray.add(cmd, (short) 4, blob); // attest issuer
    return cmd;
  }

  @Override
  public void getAttestKeyInputParameters(short arrPtr, short[] data, byte keyBlobOff,
      byte keyParametersOff,
      byte attestKeyBlobOff, byte attestKeyParamsOff, byte attestKeyIssuerOff) {
    data[keyBlobOff] = KMArray.get(arrPtr, (short) 0);
    data[keyParametersOff] = KMArray.get(arrPtr, (short) 1);
    data[attestKeyBlobOff] = KMArray.get(arrPtr, (short) 2);
    data[attestKeyParamsOff] = KMArray.get(arrPtr, (short) 3);
    data[attestKeyIssuerOff] = KMArray.get(arrPtr, (short) 4);
  }

  @Override
  public short prepareBeginResp(short paramsPtr, short opHandlePtr, short bufModePtr,
      short macLengthPtr) {
    short resp = KMArray.instance((short) 5);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, paramsPtr);
    KMArray.add(resp, (short) 2, opHandlePtr);
    KMArray.add(resp, (short) 3, bufModePtr);
    KMArray.add(resp, (short) 4, macLengthPtr);
    return resp;
  }

  @Override
  public short prepareFinishExp() {
    short byteBlob = KMByteBlob.exp();
    short cmd = KMArray.instance((short) 6);
    KMArray.add(cmd, (short) 0, KMInteger.exp());// op handle
    KMArray.add(cmd, (short) 1, byteBlob);// input data
    KMArray.add(cmd, (short) 2, byteBlob); // signature
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 3, authToken); // auth token
    short verToken = getKMVerificationTokenExp();
    KMArray.add(cmd, (short) 4, verToken); // time stamp token
    KMArray.add(cmd, (short) 5, byteBlob); // confirmation token
    return cmd;
  }

  @Override
  public short prepareUpdateExp() {
    short cmd = KMArray.instance((short) 4);
    // Arguments
    KMArray.add(cmd, (short) 0, KMInteger.exp());
    KMArray.add(cmd, (short) 1, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 2, authToken);
    short verToken = getKMVerificationTokenExp();
    KMArray.add(cmd, (short) 3, verToken);
    return cmd;
  }

  @Override
  public void getUpdateInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff,
      byte inputDataOff, byte hwTokenOff, byte verToken) {
    data[opHandleOff] = KMArray.get(arrPtr, (short) 0);
    data[inputDataOff] = KMArray.get(arrPtr, (short) 1);
    data[hwTokenOff] = KMArray.get(arrPtr, (short) 2);
    data[verToken] = KMArray.get(arrPtr, (short) 3);
  }

  @Override
  public void getFinishInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff,
      byte inputDataOff, byte signDataOff, byte hwTokenOff, byte verToken, byte confToken) {
    data[opHandleOff] = KMArray.get(arrPtr, (short) 0);
    data[inputDataOff] = KMArray.get(arrPtr, (short) 1);
    data[signDataOff] = KMArray.get(arrPtr, (short) 2);
    data[hwTokenOff] = KMArray.get(arrPtr, (short) 3);
    data[verToken] = KMArray.get(arrPtr, (short) 4);
    data[confToken] = KMArray.get(arrPtr, (short) 5);
  }

  @Override
  public short prepareFinishResp(short outputPtr) {
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, outputPtr);
    return resp;
  }

  @Override
  public short prepareUpdateResp(short outputPtr, short inputConsumedPtr) {
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, outputPtr);
    return resp;
  }

  @Override
  public void validateP1P2(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
    if (P1P2 != KEYMINT_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  @Override
  public void updateAAD(KMOperationState op, byte finish) {
    return;
  }

  @Override
  public void validatePurpose(short params) {
    short attKeyPurpose = KMKeyParameters.findTag(params, KMType.ENUM_ARRAY_TAG, KMType.PURPOSE);
    // ATTEST_KEY purpose cannot be combined with any other purpose.
    if (attKeyPurpose != KMType.INVALID_VALUE && KMEnumArrayTag.contains(attKeyPurpose,
        KMType.ATTEST_KEY)
        && KMEnumArrayTag.length(attKeyPurpose) > 1) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
  }

  public short generateBcc(boolean testMode, byte[] scratchPad) {
    if (!testMode && readBoolean(KMDataStoreConstants.PROVISIONED_LOCKED, scratchPad, (short) 0)) {
      KMException.throwIt(KMError.STATUS_FAILED);
    }
    KMDeviceUniqueKey deviceUniqueKey = rkpDataStoreInst.getDeviceUniqueKey(testMode);
    short temp = deviceUniqueKey.getPublicKey(scratchPad, (short) 0);
    short coseKey = kmCoseInst.constructCoseKey(KMInteger.uint_8(KMCose.COSE_KEY_TYPE_EC2),
        KMType.INVALID_VALUE,
        KMNInteger.uint_8(KMCose.COSE_ALG_ES256), KMInteger.uint_8(KMCose.COSE_KEY_OP_VERIFY),
        KMInteger.uint_8(KMCose.COSE_ECCURVE_256), scratchPad, (short) 0, temp,
        KMType.INVALID_VALUE, false);
    temp = encodeToApduBuffer(coseKey, scratchPad, (short) 0,
        RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);
    // Construct payload.
    short payload = kmCoseInst.constructCoseCertPayload(
        KMCosePairTextStringTag.instance(KMInteger.uint_8(KMCose.ISSUER),
            KMTextString.instance(KMCose.TEST_ISSUER_NAME, (short) 0,
                (short) KMCose.TEST_ISSUER_NAME.length)),
        KMCosePairTextStringTag.instance(KMInteger.uint_8(KMCose.SUBJECT),
            KMTextString.instance(KMCose.TEST_SUBJECT_NAME, (short) 0,
                (short) KMCose.TEST_SUBJECT_NAME.length)),
        KMCosePairByteBlobTag.instance(KMNInteger.uint_32(KMCose.SUBJECT_PUBLIC_KEY, (short) 0),
            KMByteBlob.instance(scratchPad, (short) 0, temp)),
        KMCosePairByteBlobTag.instance(KMNInteger.uint_32(KMCose.KEY_USAGE, (short) 0),
            KMByteBlob.instance(KMCose.KEY_USAGE_SIGN, (short) 0,
                (short) KMCose.KEY_USAGE_SIGN.length)));
    // temp temporarily holds the length of encoded cert payload.
    temp = encodeToApduBuffer(payload, scratchPad, (short) 0,
        RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);
    payload = KMByteBlob.instance(scratchPad, (short) 0, temp);

    // protected header
    short protectedHeader = kmCoseInst.constructHeaders(KMNInteger.uint_8(KMCose.COSE_ALG_ES256),
        KMType.INVALID_VALUE,
        KMType.INVALID_VALUE, KMType.INVALID_VALUE);
    // temp temporarily holds the length of encoded headers.
    temp = encodeToApduBuffer(protectedHeader, scratchPad, (short) 0,
        RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);
    protectedHeader = KMByteBlob.instance(scratchPad, (short) 0, temp);

    // unprotected headers.
    short arr = KMArray.instance((short) 0);
    short unprotectedHeader = KMCoseHeaders.instance(arr);

    // construct cose sign structure.
    short coseSignStructure = kmCoseInst.constructCoseSignStructure(protectedHeader,
        KMByteBlob.instance((short) 0),
        payload);
    // temp temporarily holds the length of encoded sign structure.
    // Encode cose Sign_Structure.
    temp = encodeToApduBuffer(coseSignStructure, scratchPad, (short) 0,
        RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);
    // do sign
    short len = seProvider.ecSign256(deviceUniqueKey, scratchPad, (short) 0, temp, scratchPad,
        temp);
    coseSignStructure = KMByteBlob.instance(scratchPad, temp, len);

    // construct cose_sign1
    short coseSign1 = kmCoseInst.constructCoseSign1(protectedHeader, unprotectedHeader, payload,
        coseSignStructure);

    // [Cose_Key, Cose_Sign1]
    short bcc = KMArray.instance((short) 2);
    KMArray.add(bcc, (short) 0, coseKey);
    KMArray.add(bcc, (short) 1, coseSign1);
    return bcc;
  }


  public short validateCertChain(boolean validateEekRoot, byte expCertAlg,
      byte expLeafCertAlg, short certChainArr, byte[] scratchPad, Object[] authorizedEekRoots) {
    short len = KMArray.length(certChainArr);
    short coseHeadersExp = KMCoseHeaders.exp();
    //prepare exp for coseky
    short coseKeyExp = KMCoseKey.exp();
    short ptr1;
    short ptr2;
    short signStructure;
    short encodedLen;
    short prevCoseKey = 0;
    short keySize;
    short alg = expCertAlg;
    short index;
    for (index = 0; index < len; index++) {
      ptr1 = KMArray.get(certChainArr, index);

      // validate protected Headers
      ptr2 = KMArray.get(ptr1, KMCose.COSE_SIGN1_PROTECTED_PARAMS_OFFSET);
      ptr2 = decoder.decode(coseHeadersExp, KMByteBlob.getBuffer(ptr2),
          KMByteBlob.getStartOff(ptr2), KMByteBlob.length(ptr2));
      if (!KMCoseHeaders.cast(ptr2).isDataValid(alg, KMType.INVALID_VALUE)) {
        KMException.throwIt(KMError.STATUS_FAILED);
      }

      // parse and get the public key from payload.
      ptr2 = KMArray.get(ptr1, KMCose.COSE_SIGN1_PAYLOAD_OFFSET);
      ptr2 = decoder.decode(coseKeyExp, KMByteBlob.getBuffer(ptr2),
          KMByteBlob.getStartOff(ptr2), KMByteBlob.length(ptr2));
      if ((index == (short) (len - 1)) && len > 1) {
        alg = expLeafCertAlg;
      }
      if (!KMCoseKey.cast(ptr2).isDataValid(KMCose.COSE_KEY_TYPE_EC2, KMType.INVALID_VALUE, alg,
          KMType.INVALID_VALUE, KMCose.COSE_ECCURVE_256)) {
        KMException.throwIt(KMError.STATUS_FAILED);
      }
      if (prevCoseKey == 0) {
        prevCoseKey = ptr2;
      }
      // Get the public key.
      keySize = KMCoseKey.cast(prevCoseKey).getEcdsa256PublicKey(scratchPad, (short) 0);
      if (keySize != 65) {
        KMException.throwIt(KMError.STATUS_FAILED);
      }
      if (validateEekRoot && (index == 0)) {
        boolean found = false;
        // In prod mode the first pubkey should match a well-known Google public key.
        for (short i = 0; i < (short) authorizedEekRoots.length; i++) {
          if (0 == Util.arrayCompare(scratchPad, (short) 0, (byte[]) authorizedEekRoots[i],
              (short) 0, (short) ((byte[]) authorizedEekRoots[i]).length)) {
            found = true;
            break;
          }
        }
        if (!found) {
          KMException.throwIt(KMError.STATUS_FAILED);
        }
      }
      // Validate signature.
      signStructure =
          kmCoseInst.constructCoseSignStructure(
              KMArray.get(ptr1, KMCose.COSE_SIGN1_PROTECTED_PARAMS_OFFSET),
              KMByteBlob.instance((short) 0),
              KMArray.get(ptr1, KMCose.COSE_SIGN1_PAYLOAD_OFFSET));
      encodedLen = encodeToApduBuffer(signStructure, scratchPad,
          keySize, RemotelyProvisionedComponentDevice.MAX_COSE_BUF_SIZE);

      if (!seProvider.ecVerify256(scratchPad, (short) 0, keySize, scratchPad, keySize, encodedLen,
          KMByteBlob.getBuffer(KMArray.get(ptr1, KMCose.COSE_SIGN1_SIGNATURE_OFFSET)),
          KMByteBlob.getStartOff(KMArray.get(ptr1, KMCose.COSE_SIGN1_SIGNATURE_OFFSET)),
          KMByteBlob.length(KMArray.get(ptr1, KMCose.COSE_SIGN1_SIGNATURE_OFFSET)))) {
        KMException.throwIt(KMError.STATUS_FAILED);
      }
      prevCoseKey = ptr2;
    }
    return prevCoseKey;
  }

  @Override
  protected void processGetCertChainCmd(APDU apdu) {
    KMException.throwIt(KMError.ATTESTATION_KEYS_NOT_PROVISIONED);
  }

  @Override
  public void validateEarlyBoot(short Params, byte inst, byte[] sPad, short sPadOff,
      short errorCode) {
    if (inst != INS_GENERATE_KEY_CMD) {
      //VTS expects error code EARLY_BOOT_ONLY during begin operation if eary boot ended tag is present	
      if (inst == INS_BEGIN_OPERATION_CMD) {
        errorCode = KMError.EARLY_BOOT_ENDED;
      }
      // Validate early boot
      super.validateEarlyBoot(Params, inst, sPad, sPadOff, errorCode);
    }
  }
}
