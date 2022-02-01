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
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.javacard.kmdevice;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

/**
 * KMKeymasterApplet implements the javacard applet. It creates repository and other install time
 * objects. It also implements the keymaster state machine and handles javacard applet life cycle
 * events.
 */
public class KMKeymasterDevice {

  // Constants.
  public static byte[] F4;
  public static final byte AES_BLOCK_SIZE = 16;
  public static final byte DES_BLOCK_SIZE = 8;
  public static final short MAX_LENGTH = 15000;
  public static final short WRAPPING_KEY_SIZE = 32;
  public static final short MAX_OPERATIONS_COUNT = 4;
  public static final short VERIFIED_BOOT_KEY_SIZE = 32;
  public static final short VERIFIED_BOOT_HASH_SIZE = 32;
  public static final short BOOT_PATCH_LVL_SIZE = 4;
  public static final short KEYMINT_HAL_VERSION = (short) 0x5000;
  public static final short KEYMASTER_HAL_VERSION = (short) 0x4000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  private static final short DERIVE_KEY_INPUT_SIZE = (short) 256;
  public static final byte TRUSTED_ENVIRONMENT = 1;

  // "Keymaster HMAC Verification" - used for HMAC key verification.
  public static byte[] sharingCheck;

  // "KeymasterSharedMac"
  public static byte[] ckdfLable;

  // "Auth Verification"
  public static byte[] authVerification;

  // "confirmation token"
  public static byte[] confirmationToken;
  // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
  private static byte[] defaultSubject;

  // Top 32 commands are reserved for provisioning.
  private static final byte KEYMINT_CMD_APDU_START = 0x20;

  // Master key size
  private static final short MASTER_KEY_SIZE = 16;
  private static final short HMAC_SEED_NONCE_SIZE = 32;

  protected static final byte INS_GENERATE_KEY_CMD = KEYMINT_CMD_APDU_START + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = KEYMINT_CMD_APDU_START + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = KEYMINT_CMD_APDU_START + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = KEYMINT_CMD_APDU_START + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = KEYMINT_CMD_APDU_START + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = KEYMINT_CMD_APDU_START + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = KEYMINT_CMD_APDU_START + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = KEYMINT_CMD_APDU_START + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = KEYMINT_CMD_APDU_START + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = KEYMINT_CMD_APDU_START + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = KEYMINT_CMD_APDU_START + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = KEYMINT_CMD_APDU_START + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = KEYMINT_CMD_APDU_START + 15; //0x2F
  protected static final byte INS_BEGIN_OPERATION_CMD = KEYMINT_CMD_APDU_START + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = KEYMINT_CMD_APDU_START + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = KEYMINT_CMD_APDU_START + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = KEYMINT_CMD_APDU_START + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = KEYMINT_CMD_APDU_START + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = KEYMINT_CMD_APDU_START + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = KEYMINT_CMD_APDU_START + 22; //0x36
  private static final byte INS_UPDATE_AAD_OPERATION_CMD = KEYMINT_CMD_APDU_START + 23; //0x37
  private static final byte INS_BEGIN_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 24; //0x38
  private static final byte INS_FINISH_IMPORT_WRAPPED_KEY_CMD = KEYMINT_CMD_APDU_START + 25; //0x39
  private static final byte INS_INIT_STRONGBOX_CMD = KEYMINT_CMD_APDU_START + 26; //0x3A
  // RKP
  public static final byte INS_GET_RKP_HARDWARE_INFO = KEYMINT_CMD_APDU_START + 27; //0x3B
  public static final byte INS_GENERATE_RKP_KEY_CMD = KEYMINT_CMD_APDU_START + 28; //0x3C
  public static final byte INS_BEGIN_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 29; //0x3D
  public static final byte INS_UPDATE_KEY_CMD = KEYMINT_CMD_APDU_START + 30; //0x3E
  public static final byte INS_UPDATE_EEK_CHAIN_CMD = KEYMINT_CMD_APDU_START + 31; //0x3F
  public static final byte INS_UPDATE_CHALLENGE_CMD = KEYMINT_CMD_APDU_START + 32; //0x40
  public static final byte INS_FINISH_SEND_DATA_CMD = KEYMINT_CMD_APDU_START + 33; //0x41
  public static final byte INS_GET_RESPONSE_CMD = KEYMINT_CMD_APDU_START + 34; //0x42
  private static final byte KEYMINT_CMD_APDU_END = KEYMINT_CMD_APDU_START + 35; //0x43

  private static final byte INS_END_KM_CMD = 0x7F;

  // Data Dictionary items
  private static final byte DATA_ARRAY_SIZE = 40;
  private static final byte TMP_VARIABLE_ARRAY_SIZE = 5;

  protected static final byte KEY_PARAMETERS = 0;
  private static final byte KEY_CHARACTERISTICS = 1;
  private static final byte HIDDEN_PARAMETERS = 2;
  protected static final byte HW_PARAMETERS = 3;
  private static final byte SW_PARAMETERS = 4;
  private static final byte AUTH_DATA = 5;
  private static final byte AUTH_TAG = 6;
  private static final byte NONCE = 7;
  private static final byte KEY_BLOB = 8;
  private static final byte AUTH_DATA_LENGTH = 9;
  protected static final byte SECRET = 10;
  private static final byte ROT = 11;
  private static final byte DERIVED_KEY = 12;
  private static final byte RSA_PUB_EXPONENT = 13;
  private static final byte APP_ID = 14;
  private static final byte APP_DATA = 15;
  private static final byte PUB_KEY = 16;
  private static final byte IMPORTED_KEY_BLOB = 17;
  private static final byte ORIGIN = 18;
  private static final byte NOT_USED = 19;
  private static final byte MASKING_KEY = 20;
  private static final byte HMAC_SHARING_PARAMS = 21;
  private static final byte OP_HANDLE = 22;
  private static final byte IV = 23;
  protected static final byte INPUT_DATA = 24;
  protected static final byte OUTPUT_DATA = 25;
  private static final byte HW_TOKEN = 26;
  private static final byte VERIFICATION_TOKEN = 27;
  private static final byte SIGNATURE = 28;
  private static final byte ATTEST_KEY_BLOB = 29;
  private static final byte ATTEST_KEY_PARAMS = 30;
  private static final byte ATTEST_KEY_ISSUER = 31;
  private static final byte CERTIFICATE = 32;
  private static final byte PLAIN_SECRET = 33;
  private static final byte TEE_PARAMETERS = 34;
  private static final byte SB_PARAMETERS = 35;
  private static final byte CONFIRMATION_TOKEN = 36;

  // AddRngEntropy
  private static final short MAX_SEED_SIZE = 2048;

  // Keyblob constants
  public static final byte KEY_BLOB_SECRET = 0;
  public static final byte KEY_BLOB_NONCE = 1;
  public static final byte KEY_BLOB_AUTH_TAG = 2;
  public static final byte KEY_BLOB_PARAMS = 3;
  public static final byte KEY_BLOB_PUB_KEY = 4;
  // AES GCM constants
  public static final byte AES_GCM_AUTH_TAG_LENGTH = 16;
  public static final byte AES_GCM_NONCE_LENGTH = 12;
  // ComputeHMAC constants
  private static final short HMAC_SHARED_PARAM_MAX_SIZE = 64;
  protected static final short MAX_CERT_SIZE = 2048;

  protected static final short POWER_RESET_MASK_FLAG = (short) 0x4000;

  //getHardwareInfo constants.
  private static byte[] JAVACARD_KEYMASTER_DEVICE;
  private static byte[] GOOGLE;
  private static byte[] X509Subject;

  private static short[] ATTEST_ID_TAGS;
  private static final byte SERIAL_NUM = (byte) 0x01;

  protected KMDecoder decoder;
  protected KMRepository repository;
  // TODO Remove static
  protected static KMEncoder encoder;
  protected KMSEProvider seProvider;
  protected KMDataStore storeDataInst;
  protected KMBootDataStore bootParamsProv;
  protected KMOperationState[] opTable;
  protected short[] tmpVariables;
  protected static short[] data;
  protected byte[] wrappingKey;


  /**
   * Registers this applet.
   */
  public KMKeymasterDevice(KMSEProvider seImpl, KMRepository repoInst, KMEncoder encoderInst,
      KMDecoder decoderInst, KMDataStore storeData,
      KMBootDataStore bootParamsProvider) {
    initKMDeviceStatics();
    seProvider = seImpl;
    bootParamsProv = bootParamsProvider;
    storeDataInst = storeData;
    repository = repoInst;
    encoder = encoderInst;
    decoder = decoderInst;
    data = JCSystem.makeTransientShortArray(DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_DESELECT);
    tmpVariables = JCSystem.makeTransientShortArray(TMP_VARIABLE_ARRAY_SIZE,
        JCSystem.CLEAR_ON_DESELECT);
    wrappingKey = JCSystem.makeTransientByteArray((short) (WRAPPING_KEY_SIZE + 1),
        JCSystem.CLEAR_ON_RESET);
    resetWrappingKey();
    opTable = new KMOperationState[MAX_OPERATIONS_COUNT];
    short index = 0;
    while (index < MAX_OPERATIONS_COUNT) {
      opTable[index] = new KMOperationState();
      index++;
    }
    KMType.initialize();
    if (!seProvider.isUpgrading()) {
      initializeDefaultValues();
    }

  }

  private void initializeDefaultValues() {
    short offset = repository.alloc((short) 32);
    // Initialize master key
    byte[] buffer = repository.getHeap();
    seProvider.getTrueRandomNumber(buffer, offset, MASTER_KEY_SIZE);
    storeDataInst.storeData(KMDataStoreConstants.MASTER_KEY, buffer, offset, MASTER_KEY_SIZE);
    // initialize default values
    initHmacNonceAndSeed(buffer, offset);
    initSystemBootParams();
    writeBoolean(KMDataStoreConstants.DEVICE_LOCKED, false, buffer, offset);
    writeBoolean(KMDataStoreConstants.DEVICE_LOCKED_PASSWORD_ONLY, false, buffer, offset);
    writeBoolean(KMDataStoreConstants.BOOT_ENDED_STATUS, false, buffer, offset);
    writeBoolean(KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS, false, buffer, offset);
    writeBoolean(KMDataStoreConstants.PROVISIONED_LOCKED, false, buffer, offset);
  }

  public static void initStatics() {
    F4 = new byte[]{0x01, 0x00, 0x01};
    // "Keymaster HMAC Verification" - used for HMAC key verification.
    sharingCheck = new byte[]{
        0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x48, 0x4D, 0x41, 0x43, 0x20,
        0x56,
        0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
    };

    // "KeymasterSharedMac"
    ckdfLable = new byte[]{
        0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64,
        0x4D,
        0x61, 0x63
    };

    // "Auth Verification"
    authVerification = new byte[]{
        0x41, 0x75, 0x74, 0x68, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
        0x6F,
        0x6E
    };
    // "confirmation token"
    confirmationToken = new byte[]{
        0x63, 0x6F, 0x6E, 0x66, 0x69, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F,
        0x6B,
        0x65, 0x6E
    };
    // Subject is a fixed field with only CN= Android Keystore Key - same for all the keys
    defaultSubject = new byte[]{
        0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e,
        0x64,
        0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B,
        0x65,
        0x79
    };
    //getHardwareInfo constants.
    JAVACARD_KEYMASTER_DEVICE = new byte[]{
        0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
        0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
    };
    GOOGLE = new byte[]{0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};
    X509Subject = new byte[]{
        0x30, 0x1F, 0x31, 0x1D, 0x30, 0x1B, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x14, 0x41, 0x6e,
        0x64,
        0x72, 0x6f, 0x69, 0x64, 0x20, 0x4B, 0x65, 0x79, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x20, 0x4B,
        0x65,
        0x79
    };

    ATTEST_ID_TAGS = new short[]{
        KMType.ATTESTATION_ID_BRAND,
        KMType.ATTESTATION_ID_DEVICE,
        KMType.ATTESTATION_ID_IMEI,
        KMType.ATTESTATION_ID_MANUFACTURER,
        KMType.ATTESTATION_ID_MEID,
        KMType.ATTESTATION_ID_MODEL,
        KMType.ATTESTATION_ID_PRODUCT,
        KMType.ATTESTATION_ID_SERIAL
    };
  }

  private static void initKMDeviceStatics() {
    initStatics();
    KMAttestationCertImpl.initStatics();
    KMBignumTag.initStatics();
    KMCosePairCoseKeyTag.initStatics();
    KMEnumTag.initStatics();
    KMCosePairTextStringTag.initStatics();
    KMByteTag.initStatics();
    KMEnum.initStatics();
    KMIntegerTag.initStatics();
    KMCose.initStatics();
    KMKeyParameters.initStatics();
    KMUtils.initStatics();
    KMBoolTag.initStatics();
    KMPKCS8Decoder.initStatics();
    KMEnumArrayTag.initStatics();
    KMIntegerArrayTag.initStatics();
  }

  public void clean() {
    repository.clean();
  }

  protected void initHmacNonceAndSeed(byte[] scratchPad, short offset) {
    seProvider.newRandomNumber(scratchPad, offset, HMAC_SEED_NONCE_SIZE);
    storeDataInst.storeData(KMDataStoreConstants.HMAC_NONCE, scratchPad, offset,
        HMAC_SEED_NONCE_SIZE);
  }

  private void releaseAllOperations() {
    short index = 0;
    while (index < MAX_OPERATIONS_COUNT) {
      opTable[index].reset();
      index++;
    }
  }

  private KMOperationState reserveOperation(short algorithm, short opHandle) {
    short index = 0;
    while (index < MAX_OPERATIONS_COUNT) {
      if (opTable[index].getAlgorithm() == KMType.INVALID_VALUE) {
        opTable[index].reset();
        opTable[index].setAlgorithm(algorithm);
        opTable[index].setHandle(KMInteger.getBuffer(opHandle),
            KMInteger.getStartOff(opHandle),
            KMInteger.length(opHandle));
        return opTable[index];
      }
      index++;
    }
    return null;
  }

  private KMOperationState findOperation(short handle) {
    return findOperation(KMInteger.getBuffer(handle),
        KMInteger.getStartOff(handle),
        KMInteger.length(handle));
  }

  private KMOperationState findOperation(byte[] opHandle, short start, short len) {
    short index = 0;
    while (index < MAX_OPERATIONS_COUNT) {
      if (opTable[index].compare(opHandle, start, len) == 0) {
        if (opTable[index].getAlgorithm() != KMType.INVALID_VALUE) {
          return opTable[index];
        }
      }
      index++;
    }
    return null;
  }

  private void releaseOperation(KMOperationState op) {
    op.reset();
  }

  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  public boolean onSelect() {
    repository.onSelect();
    return true;
  }

  /**
   * De-selects this applet.
   */
  public void onDeselect() {
    repository.onDeselect();
  }

  public void onUninstall() {
    repository.onUninstall();
  }

  public short mapISOErrorToKMError(short reason) {
    switch (reason) {
      case ISO7816.SW_CLA_NOT_SUPPORTED:
        return KMError.UNSUPPORTED_CLA;
      case ISO7816.SW_CONDITIONS_NOT_SATISFIED:
        return KMError.SW_CONDITIONS_NOT_SATISFIED;
      case ISO7816.SW_COMMAND_NOT_ALLOWED:
        return KMError.CMD_NOT_ALLOWED;
      case ISO7816.SW_DATA_INVALID:
        return KMError.INVALID_DATA;
      case ISO7816.SW_INCORRECT_P1P2:
        return KMError.INVALID_P1P2;
      case ISO7816.SW_INS_NOT_SUPPORTED:
        return KMError.UNSUPPORTED_INSTRUCTION;
      case ISO7816.SW_WRONG_LENGTH:
        return KMError.SW_WRONG_LENGTH;
      case ISO7816.SW_UNKNOWN:
      default:
        return KMError.UNKNOWN_ERROR;
    }
  }

  public short mapCryptoErrorToKMError(short reason) {
    switch (reason) {
      case CryptoException.ILLEGAL_USE:
        return KMError.CRYPTO_ILLEGAL_USE;
      case CryptoException.ILLEGAL_VALUE:
        return KMError.CRYPTO_ILLEGAL_VALUE;
      case CryptoException.INVALID_INIT:
        return KMError.CRYPTO_INVALID_INIT;
      case CryptoException.NO_SUCH_ALGORITHM:
        return KMError.CRYPTO_NO_SUCH_ALGORITHM;
      case CryptoException.UNINITIALIZED_KEY:
        return KMError.CRYPTO_UNINITIALIZED_KEY;
      default:
        return KMError.UNKNOWN_ERROR;
    }
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   *
   * @param apdu the incoming APDU
   */
  public void process(APDU apdu) {
    try {
      resetData();
      repository.onProcess();
      // Validate APDU Header.
      byte[] apduBuffer = apdu.getBuffer();
      byte apduIns = apduBuffer[ISO7816.OFFSET_INS];

      switch (apduIns) {
        case INS_INIT_STRONGBOX_CMD:
          processInitStrongBoxCmd(apdu);
          sendError(apdu, KMError.OK);
          return;
        case INS_GENERATE_KEY_CMD:
          processGenerateKey(apdu);
          break;
        case INS_ATTEST_KEY_CMD:
          processAttestKeyCmd(apdu);
          break;
        case INS_IMPORT_KEY_CMD:
          processImportKeyCmd(apdu);
          break;
        case INS_IMPORT_WRAPPED_KEY_CMD:
          processImportWrappedKeyCmd(apdu);
          break;
        case INS_BEGIN_IMPORT_WRAPPED_KEY_CMD:
          processBeginImportWrappedKeyCmd(apdu);
          break;
        case INS_FINISH_IMPORT_WRAPPED_KEY_CMD:
          processFinishImportWrappedKeyCmd(apdu);
          break;
        case INS_EXPORT_KEY_CMD:
          processExportKeyCmd(apdu);
          break;
        case INS_UPGRADE_KEY_CMD:
          processUpgradeKeyCmd(apdu);
          break;
        case INS_DELETE_KEY_CMD:
          processDeleteKeyCmd(apdu);
          break;
        case INS_DELETE_ALL_KEYS_CMD:
          processDeleteAllKeysCmd(apdu);
          break;
        case INS_ADD_RNG_ENTROPY_CMD:
          processAddRngEntropyCmd(apdu);
          break;
        case INS_COMPUTE_SHARED_HMAC_CMD:
          processComputeSharedHmacCmd(apdu);
          break;
        case INS_DESTROY_ATT_IDS_CMD:
          processDestroyAttIdsCmd(apdu);
          break;
        case INS_VERIFY_AUTHORIZATION_CMD:
          processVerifyAuthorizationCmd(apdu);
          break;
        case INS_GET_HMAC_SHARING_PARAM_CMD:
          processGetHmacSharingParamCmd(apdu);
          break;
        case INS_GET_KEY_CHARACTERISTICS_CMD:
          processGetKeyCharacteristicsCmd(apdu);
          break;
        case INS_GET_HW_INFO_CMD:
          processGetHwInfoCmd(apdu);
          break;
        case INS_BEGIN_OPERATION_CMD:
          processBeginOperationCmd(apdu);
          break;
        case INS_UPDATE_OPERATION_CMD:
          processUpdateOperationCmd(apdu);
          break;
        case INS_FINISH_OPERATION_CMD:
          processFinishOperationCmd(apdu);
          break;
        case INS_ABORT_OPERATION_CMD:
          processAbortOperationCmd(apdu);
          break;
        case INS_DEVICE_LOCKED_CMD:
          processDeviceLockedCmd(apdu);
          break;
        case INS_EARLY_BOOT_ENDED_CMD:
          processEarlyBootEndedCmd(apdu);
          break;
        case INS_UPDATE_AAD_OPERATION_CMD:
          processUpdateAadOperationCmd(apdu);
          break;
        case INS_GET_CERT_CHAIN_CMD:
          processGetCertChainCmd(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
    } catch (KMException exception) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, KMException.reason());
    } catch (ISOException exp) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      freeOperations();
      resetWrappingKey();
      sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      repository.clean();
    }
  }

  private void generateUniqueOperationHandle(byte[] buf, short offset, short len) {
    do {
      seProvider.newRandomNumber(buf, offset, len);
    } while (null != findOperation(buf, offset, len));
  }

  private void freeOperations() {
    if (data[OP_HANDLE] != KMType.INVALID_VALUE) {
      KMOperationState op = findOperation(data[OP_HANDLE]);
      if (op != null) {
        releaseOperation(op);
      }
    }
  }

  private void processEarlyBootEndedCmd(APDU apdu) {
    writeBoolean(KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS, true);
  }

  private short deviceLockedCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 2);
    // passwordOnly
    KMArray.add(cmd, (short) 0, KMInteger.exp());
    // verification token
    KMArray.add(cmd, (short) 1, getKMVerificationTokenExp());
    return receiveIncoming(apdu, cmd);
  }

  protected boolean isProvisionLocked(byte[] scratchPad, short scratchPadOff) {
    return readBoolean(KMDataStoreConstants.PROVISIONED_LOCKED, scratchPad, scratchPadOff);
  }

  protected boolean readBoolean(byte storeDataId, byte[] scratchPad, short scratchPadOff) {
    short len = storeDataInst.getData(storeDataId, scratchPad, scratchPadOff);
    if (len == 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return scratchPad[scratchPadOff] == 0x01;
  }

  protected void writeBoolean(byte storeDataId, boolean flag, byte[] scratchPad, short offset) {
    if (flag) {
      scratchPad[offset] = (byte) 0x01;
    } else {
      scratchPad[offset] = (byte) 0x00;
    }
    storeDataInst.storeData(storeDataId, scratchPad, offset, (short) 1);
  }

  protected void writeBoolean(byte storeDataId, boolean flag) {
    short start = repository.alloc((short) 1);
    byte[] buffer = repository.getHeap();
    writeBoolean(storeDataId, flag, buffer, start);
  }

  protected void writeData(byte storeDataId, byte[] data, short offset, short len) {
    storeDataInst.storeData(storeDataId, data, offset, len);
  }

  protected short readData(byte storeDataId, byte[] scratchPad, short offset) {
    short len = storeDataInst.getData(storeDataId, scratchPad, offset);
    if (len == 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    return len;
  }

  protected short readBlob(byte storeDataId, byte[] scratchPad, short offset) {
    short len = readData(storeDataId, scratchPad, offset);
    return KMByteBlob.instance(scratchPad, offset, len);
  }

  protected short readInteger32(byte storeDataId, byte[] scratchPad, short offset) {
    readData(storeDataId, scratchPad, offset);
    return KMInteger.uint_32(scratchPad, offset);
  }

  protected short readInteger64(byte storeDataId, byte[] scratchPad, short offset) {
    readData(storeDataId, scratchPad, offset);
    return KMInteger.uint_64(scratchPad, offset);
  }

  private void processDeviceLockedCmd(APDU apdu) {
    short cmd = deviceLockedCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short passwordOnly = KMArray.get(cmd, (short) 0);
    short verToken = KMArray.get(cmd, (short) 1);
    passwordOnly = KMInteger.getByte(passwordOnly);
    validateVerificationToken(verToken, scratchPad);
    short verTime = KMVerificationToken.getTimestamp(verToken);
    short len = storeDataInst.getData(KMDataStoreConstants.DEVICE_LOCKED_TIME, scratchPad,
        (short) 0);
    short lastDeviceLockedTime = KMByteBlob.instance(scratchPad, (short) 0, len);
    if (KMInteger.compare(verTime, lastDeviceLockedTime) > 0) {
      Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
      KMInteger.getValue(verTime, scratchPad, (short) 0, (short) 8);
      writeBoolean(KMDataStoreConstants.DEVICE_LOCKED, true);
      writeBoolean(KMDataStoreConstants.DEVICE_LOCKED_PASSWORD_ONLY, passwordOnly == 0x01);
      storeDataInst.storeData(KMDataStoreConstants.DEVICE_LOCKED_TIME, scratchPad, (short) 0,
          (short) 8);
    }
    sendError(apdu, KMError.OK);
  }

  private void resetWrappingKey() {
    if (!isValidWrappingKey()) {
      return;
    }
    Util.arrayFillNonAtomic(wrappingKey, (short) 1, WRAPPING_KEY_SIZE, (byte) 0);
    wrappingKey[0] = -1;
  }

  private boolean isValidWrappingKey() {
    return wrappingKey[0] != -1;
  }

  private void setWrappingKey(short key) {
    if (KMByteBlob.length(key) != WRAPPING_KEY_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    wrappingKey[0] = 0;
    Util.arrayCopyNonAtomic(KMByteBlob.getBuffer(key),
        KMByteBlob.getStartOff(key), wrappingKey, (short) 1, WRAPPING_KEY_SIZE);
  }

  private short getWrappingKey() {
    return KMByteBlob.instance(wrappingKey, (short) 1, WRAPPING_KEY_SIZE);
  }

  protected void resetData() {
    short index = 0;
    while (index < data.length) {
      data[index] = KMType.INVALID_VALUE;
      index++;
    }
    index = 0;
    while (index < tmpVariables.length) {
      tmpVariables[index] = KMType.INVALID_VALUE;
      index++;
    }
  }

  /**
   * Sends a response, may be extended response, as requested by the command.
   */
  public void sendOutgoing(APDU apdu, short resp) {
    //TODO handle the extended buffer stuff. We can reuse this.
    short bufferStartOffset = repository.allocAvailableMemory();
    byte[] buffer = repository.getHeap();
    // TODO we can change the following to incremental send.
    short bufferLength = encoder.encode(resp, buffer, bufferStartOffset);
    if (((short) (bufferLength + bufferStartOffset)) > ((short) repository
        .getHeap().length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    apdu.setOutgoing();
    apdu.setOutgoingLength(bufferLength);
    apdu.sendBytesLong(buffer, bufferStartOffset, bufferLength);
  }

  /**
   * Receives data, which can be extended data, as requested by the command instance.
   */
  public short receiveIncoming(APDU apdu, short reqExp) {
    short recvLen = apdu.setIncomingAndReceive();
    short bufferLength = apdu.getIncomingLength();
    short bufferStartOffset = repository.allocReclaimableMemory(bufferLength);
    short req = receiveIncoming(apdu, reqExp, repository.getHeap(), bufferLength, bufferStartOffset,
        recvLen);
    repository.reclaimMemory(bufferLength);
    return req;
  }

  public short receiveIncoming(APDU apdu, short reqExp, byte[] reclamBuf, short bLen,
      short bStartOffset, short incomingReceivedLen) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = incomingReceivedLen;
    short srcOffset = apdu.getOffsetCdata();
    // TODO add logic to handle the extended length buffer. In this case the memory can be reused
    //  from extended buffer.
    short index = bStartOffset;
    while (recvLen > 0 && ((short) (index - bStartOffset) < bLen)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, reclamBuf, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    return decoder.decode(reqExp, reclamBuf, bStartOffset, bLen);
  }

  public void receiveIncomingCertData(APDU apdu, byte[] reclamBuf, short bLen, short bStartOffset,
      short incomingReceivedLen, byte[] outBuf, short outOff) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = incomingReceivedLen;
    short srcOffset = apdu.getOffsetCdata();
    short index = bStartOffset;
    while (recvLen > 0 && ((short) (index - bStartOffset) < bLen)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, reclamBuf, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    decoder.decodeCertificateData((short) 3,
        reclamBuf, bStartOffset, bLen,
        outBuf, outOff);
  }


  private void processGetHwInfoCmd(APDU apdu) {
    // No arguments expected
    short respPtr = getHardwareInfo();
    // send buffer to master
    sendOutgoing(apdu, respPtr);
  }

  private short addRngEntropyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 1);
    // Rng entropy
    KMArray.add(cmd, (short) 0, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    short cmd = addRngEntropyCmd(apdu);
    // Process
    short blob = KMArray.get(cmd, (short) 0);
    // Maximum 2KiB of seed is allowed.
    if (KMByteBlob.length(blob) > MAX_SEED_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    seProvider.addRngEntropy(KMByteBlob.getBuffer(blob), KMByteBlob.getStartOff(blob),
        KMByteBlob.length(blob));
    sendError(apdu, KMError.OK);
  }

  private short getKeyCharacteristicsCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 3);
    KMArray.add(cmd, (short) 0, KMByteBlob.exp());
    KMArray.add(cmd, (short) 1, KMByteBlob.exp());
    KMArray.add(cmd, (short) 2, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processGetKeyCharacteristicsCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    short cmd = getKeyCharacteristicsCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_BLOB] = KMArray.get(cmd, (short) 0);
    data[APP_ID] = KMArray.get(cmd, (short) 1);
    data[APP_DATA] = KMArray.get(cmd, (short) 2);
    if (!KMByteBlob.isValid(data[APP_ID])) {
      data[APP_ID] = KMType.INVALID_VALUE;
    }
    if (!KMByteBlob.isValid(data[APP_DATA])) {
      data[APP_DATA] = KMType.INVALID_VALUE;
    }
    // Parse Key Blob
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    // Check Version and Patch Level
    checkVersionAndPatchLevel(scratchPad);
    // Remove custom tags from key characteristics
    short teeParams = KMKeyCharacteristics.getTeeEnforced(data[KEY_CHARACTERISTICS]);
    if (teeParams != KMType.INVALID_VALUE) {
      KMKeyParameters.deleteCustomTags(teeParams);
    }
    // make response.
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, data[KEY_CHARACTERISTICS]);
    sendOutgoing(apdu, resp);
  }

  private void processGetHmacSharingParamCmd(APDU apdu) {
    // No Arguments
    // Create HMAC Sharing Parameters
    byte[] scratchPad = apdu.getBuffer();
    short params = KMHmacSharingParameters.instance();
    short nonce = readBlob(KMDataStoreConstants.HMAC_NONCE, scratchPad, (short) 0);
    short seed = KMByteBlob.instance((short) 0);
    KMHmacSharingParameters.setNonce(params, nonce);
    KMHmacSharingParameters.setSeed(params, seed);
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, params);
    sendOutgoing(apdu, resp);
  }

  private void processDeleteAllKeysCmd(APDU apdu) {
    // No arguments
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private short deleteKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private short keyBlob() {
    short keyBlob = KMArray.instance((short) 5);
    KMArray.add(keyBlob, KMKeymasterDevice.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.add(keyBlob, KMKeymasterDevice.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.add(keyBlob, KMKeymasterDevice.KEY_BLOB_NONCE, KMByteBlob.exp());
    short keyChar = getKeyCharacteristicsExp();
    KMArray.add(keyBlob, KMKeymasterDevice.KEY_BLOB_PARAMS, keyChar);
    KMArray.add(keyBlob, KMKeymasterDevice.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    return keyBlob;
  }

  private void processDeleteKeyCmd(APDU apdu) {
    short cmd = deleteKeyCmd(apdu);
    data[KEY_BLOB] = KMArray.get(cmd, (short) 0);
    try {
      data[KEY_BLOB] = decoder.decodeArray(keyBlob(),
          KMByteBlob.getBuffer(data[KEY_BLOB]),
          KMByteBlob.getStartOff(data[KEY_BLOB]),
          KMByteBlob.length(data[KEY_BLOB]));
    } catch (ISOException e) {
      // As per VTS, deleteKey should return KMError.OK but in case if
      // input is empty then VTS accepts UNIMPLEMENTED errorCode as well.
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    if (KMArray.length(data[KEY_BLOB]) < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private short computeSharedHmacCmd(APDU apdu) {
    short params = KMHmacSharingParameters.exp();
    short paramsVec = KMArray.exp(params);
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, paramsVec);
    return receiveIncoming(apdu, cmd);
  }

  private void processComputeSharedHmacCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = computeSharedHmacCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[HMAC_SHARING_PARAMS] = KMArray.get(cmd, (short) 0);
    // Concatenate HMAC Params
    //tmpVariables[0]
    short paramsLen = KMArray.length(data[HMAC_SHARING_PARAMS]); // total number of params
    //tmpVariables[1]
    short concateBuffer = repository.alloc((short) (paramsLen * HMAC_SHARED_PARAM_MAX_SIZE));
    //tmpVariables[2]
    short paramIndex = 0; // index for params
    //tmpVariables[3]
    short bufferIndex = 0; // index for concatenation buffer
    // To check if nonce created by Strongbox is found. This value becomes 1 if both
    // seed and nonce created here are found in hmac sharing parameters received.
    //tmpVariables[7] = 0;
    short found = 0;
    //tmpVariables[9]
    short nonce = readBlob(KMDataStoreConstants.HMAC_NONCE, scratchPad, (short) 0);

    while (paramIndex < paramsLen) {
      // read HmacSharingParam
      //tmpVariables[4]
      short param = KMArray.get(data[HMAC_SHARING_PARAMS], paramIndex);
      // get seed - 32 bytes max
      //tmpVariables[5]
      short seed = KMHmacSharingParameters.getSeed(param);
      //tmpVariables[6]
      short seedLength = KMByteBlob.length(seed);
      // if seed is present
      if (seedLength != 0) {
        // then copy that to concatenation buffer
        Util.arrayCopyNonAtomic(
            KMByteBlob.getBuffer(seed),
            KMByteBlob.getStartOff(seed),
            repository.getHeap(),
            (short) (concateBuffer + bufferIndex), // concat index
            seedLength);
        bufferIndex += seedLength; // increment the concat index
      } else if (found == 0) {
        found = 1; // Applet does not have any seed. Potentially
      }
      // if nonce is present get nonce - 32 bytes
      //tmpVariables[5]
      short paramNonce = KMHmacSharingParameters.getNonce(param);
      short nonceLen = KMByteBlob.length(paramNonce);
      // if nonce is less then 32 - it is an error
      if (nonceLen < 32) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      // copy nonce to concatenation buffer
      Util.arrayCopyNonAtomic(
          KMByteBlob.getBuffer(paramNonce),
          KMByteBlob.getStartOff(paramNonce),
          repository.getHeap(),
          (short) (concateBuffer + bufferIndex), // index
          nonceLen);

      // Check if the nonce generated here is present in the hmacSharingParameters array.
      // Otherwise throw INVALID_ARGUMENT error.
      if (found == 1) {
        if (0
            == Util.arrayCompare(
            repository.getHeap(),
            (short) (concateBuffer + bufferIndex),
            KMByteBlob.getBuffer(nonce),
            KMByteBlob.getStartOff(nonce),
            nonceLen)) {
          found = 2; // hmac nonce for this keymaster found.
        } else {
          found = 0;
        }
      }
      bufferIndex += nonceLen; // increment by nonce length
      paramIndex++; // go to next hmac param in the vector
    }
    if (found != 2) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // generate the key and store it in scratch pad - 32 bytes
    //tmpVariables[6]
    short keyLen =
        seProvider.cmacKDF(
            storeDataInst.getPresharedKey(),
            ckdfLable,
            (short) 0,
            (short) ckdfLable.length,
            repository.getHeap(),
            concateBuffer,
            bufferIndex,
            scratchPad,
            (short) 0);

    // persist the computed hmac key.
    writeData(KMDataStoreConstants.COMPUTED_HMAC_KEY, scratchPad, (short) 0, keyLen);
    // Generate sharingKey verification signature and store that in scratch pad.
    //tmpVariables[5]
    short signLen =
        seProvider.hmacSign(
            scratchPad,
            (short) 0,
            keyLen,
            sharingCheck,
            (short) 0,
            (short) sharingCheck.length,
            scratchPad,
            keyLen);
    // verification signature blob - 32 bytes
    //tmpVariables[1]
    short signature = KMByteBlob.instance(scratchPad, keyLen, signLen);
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, signature);
    sendOutgoing(apdu, resp);
  }

  private short upgradeKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 2);
    short keyParams = KMKeyParameters.exp();
    KMArray.add(cmd, (short) 0, KMByteBlob.exp()); // Key Blob
    KMArray.add(cmd, (short) 1, keyParams); // Key Params
    return receiveIncoming(apdu, cmd);
  }

  private boolean isKeyUpgradeRequired(short tag, short systemParam) {
    // validate the tag and check if key needs upgrade.
    short tagValue = KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.UINT_TAG, tag);
    tagValue = KMIntegerTag.getValue(tagValue);
    short zero = KMInteger.uint_8((byte) 0);
    if (tagValue != KMType.INVALID_VALUE) {
      // OS version in key characteristics must be less the OS version stored in Javacard or the
      // stored version must be zero. Then only upgrade is allowed else it is invalid argument.
      if ((tag == KMType.OS_VERSION
          && KMInteger.compare(tagValue, systemParam) == 1
          && KMInteger.compare(systemParam, zero) == 0)) {
        // Key needs upgrade.
        return true;
      } else if ((KMInteger.compare(tagValue, systemParam) == -1)) {
        // Each os version or patch level associated with the key must be less than it's
        // corresponding value stored in Javacard, then only upgrade is allowed otherwise it
        // is invalid argument.
        return true;
      } else if (KMInteger.compare(tagValue, systemParam) == 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
    }
    return false;
  }

  private void processUpgradeKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = upgradeKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();

    data[KEY_BLOB] = KMArray.get(cmd, (short) 0);
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 1);
    //tmpVariables[0]
    short appId =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_ID);
    if (appId != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.getValue(appId);
    }
    short appData =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_DATA);
    if (appData != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.getValue(appData);
    }
    // parse existing key blob
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    boolean isKeyUpgradeRequired = false;
    // Check if key requires upgrade.
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.OS_VERSION,
        readInteger32(KMDataStoreConstants.OS_VERSION, scratchPad, (short) 0));
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.OS_PATCH_LEVEL,
        readInteger32(KMDataStoreConstants.OS_PATCH_LEVEL, scratchPad, (short) 0));
    isKeyUpgradeRequired |=
        isKeyUpgradeRequired(KMType.VENDOR_PATCH_LEVEL,
            readInteger32(KMDataStoreConstants.VENDOR_PATCH_LEVEL, scratchPad, (short) 0));
    // Get boot patch level.
    bootParamsProv.getBootPatchLevel(scratchPad, (short) 0);
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.BOOT_PATCH_LEVEL,
        KMInteger.uint_32(scratchPad, (short) 0));

    if (isKeyUpgradeRequired) {
      // copy origin
      data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
      makeKeyCharacteristics(scratchPad);
      // create new key blob with current os version etc.
      createEncryptedKeyBlob(scratchPad);
    } else {
      data[KEY_BLOB] = KMByteBlob.instance((short) 0);
    }
    // prepare the response
    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, data[KEY_BLOB]);
    sendOutgoing(apdu, resp);
  }

  private void processExportKeyCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processWrappingKeyBlob(short keyBlob, short wrapParams, byte[] scratchPad) {
    // Read App Id and App Data if any from un wrapping key params
    short appId =
        KMKeyParameters.findTag(wrapParams, KMType.BYTES_TAG, KMType.APPLICATION_ID);
    short appData =
        KMKeyParameters.findTag(wrapParams, KMType.BYTES_TAG, KMType.APPLICATION_DATA);
    if (appId != KMTag.INVALID_VALUE) {
      appId = KMByteTag.getValue(appId);
    }
    if (appData != KMTag.INVALID_VALUE) {
      appData = KMByteTag.getValue(appData);
    }
    data[APP_ID] = appId;
    data[APP_DATA] = appData;
    data[KEY_PARAMETERS] = wrapParams;
    data[KEY_BLOB] = keyBlob;
    // parse the wrapping key blob
    parseEncryptedKeyBlob(keyBlob, appId, appData, scratchPad);
    validateWrappingKeyBlob();
  }

  private void validateWrappingKeyBlob() {
    // check whether the wrapping key is RSA with purpose KEY_WRAP, padding RSA_OAEP and Digest
    // SHA2_256.
    KMTag.assertPresence(data[SB_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM,
        KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    if (KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]) != KMType.RSA) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    }
    if (!KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if (!KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_OAEP, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    if (!KMEnumArrayTag.contains(KMType.PURPOSE, KMType.WRAP_KEY, data[HW_PARAMETERS])) {
      KMException.throwIt((KMError.INCOMPATIBLE_PURPOSE));
    }
  }

  private short decryptTransportKey(short privExp, short modulus, short transportKey,
      byte[] scratchPad) {
    short length =
        seProvider.rsaDecipherOAEP256(
            KMByteBlob.getBuffer(privExp),
            KMByteBlob.getStartOff(privExp),
            KMByteBlob.length(privExp),
            KMByteBlob.getBuffer(modulus),
            KMByteBlob.getStartOff(modulus),
            KMByteBlob.length(modulus),
            KMByteBlob.getBuffer(transportKey),
            KMByteBlob.getStartOff(transportKey),
            KMByteBlob.length(transportKey),
            scratchPad,
            (short) 0);
    return KMByteBlob.instance(scratchPad, (short) 0, length);

  }

  private void unmask(short data, short maskingKey) {
    short dataLength = KMByteBlob.length(data);
    short maskLength = KMByteBlob.length(maskingKey);
    // Length of masking key and transport key must be same.
    if (maskLength != dataLength) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    short index = 0; // index
    // Xor every byte of masking and key and store the result in data[SECRET]
    while (index < maskLength) {
      short var1 =
          (short) (((short) KMByteBlob.get(maskingKey, index)) & 0x00FF);
      short var2 =
          (short) (((short) KMByteBlob.get(data, index)) & 0x00FF);
      KMByteBlob.add(data, index, (byte) (var1 ^ var2));
      index++;
    }
  }

  private short beginImportWrappedKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 4);
    short params = KMKeyParameters.expAny();
    KMArray.add(cmd, (short) 0, KMByteBlob.exp()); // Encrypted Transport Key
    KMArray.add(cmd, (short) 1, KMByteBlob.exp()); // Wrapping Key KeyBlob
    KMArray.add(cmd, (short) 2, KMByteBlob.exp()); // Masking Key
    params = KMKeyParameters.exp();
    KMArray.add(cmd, (short) 3, params); // Wrapping key blob Params
    return receiveIncoming(apdu, cmd);
  }

  private void processBeginImportWrappedKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = beginImportWrappedKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    // Step -1 parse the wrapping key blob
    // read wrapping key blob
    short keyBlob = KMArray.get(cmd, (short) 1);
    // read un wrapping key params
    short wrappingKeyParameters = KMArray.get(cmd, (short) 3);
    processWrappingKeyBlob(keyBlob, wrappingKeyParameters, scratchPad);
    // Step 2 - decrypt the encrypted transport key - 32 bytes AES-GCM key
    short transportKey = decryptTransportKey(data[SECRET], data[PUB_KEY],
        KMArray.get(cmd, (short) 0), scratchPad);
    // Step 3 - XOR the decrypted AES-GCM key with with masking key
    unmask(transportKey, KMArray.get(cmd, (short) 2));
    if (isValidWrappingKey()) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    setWrappingKey(transportKey);
    sendError(apdu, KMError.OK);
  }

  private short aesGCMDecrypt(short aesSecret, short input, short nonce, short authData,
      short authTag, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, KMByteBlob.length(input), (byte) 0);
    if (!seProvider.aesGCMDecrypt(
        KMByteBlob.getBuffer(aesSecret),
        KMByteBlob.getStartOff(aesSecret),
        KMByteBlob.length(aesSecret),
        KMByteBlob.getBuffer(input),
        KMByteBlob.getStartOff(input),
        KMByteBlob.length(input),
        scratchPad,
        (short) 0,
        KMByteBlob.getBuffer(nonce),
        KMByteBlob.getStartOff(nonce),
        KMByteBlob.length(nonce),
        KMByteBlob.getBuffer(authData),
        KMByteBlob.getStartOff(authData),
        KMByteBlob.length(authData),
        KMByteBlob.getBuffer(authTag),
        KMByteBlob.getStartOff(authTag),
        KMByteBlob.length(authTag))) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
    return KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.length(input));
  }

  private short finishImportWrappedKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 8);
    short params = KMKeyParameters.expAny();
    KMArray.add(cmd, (short) 0, params); // Key Params of wrapped key
    KMArray.add(cmd, (short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.add(cmd, (short) 2, KMByteBlob.exp()); // Wrapped Import Key Blob
    KMArray.add(cmd, (short) 3, KMByteBlob.exp()); // Auth Tag
    KMArray.add(cmd, (short) 4, KMByteBlob.exp()); // IV - Nonce
    KMArray.add(cmd, (short) 5, KMByteBlob.exp()); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.add(cmd, (short) 6, KMInteger.exp()); // Password Sid
    KMArray.add(cmd, (short) 7, KMInteger.exp()); // Biometric Sid
    return receiveIncoming(apdu, cmd);
  }

  //TODO remove cmd later on
  private void processFinishImportWrappedKeyCmd(APDU apdu) {
    short cmd = finishImportWrappedKeyCmd(apdu);
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 0);
    short keyFmt = KMArray.get(cmd, (short) 1);
    keyFmt = KMEnum.getVal(keyFmt);
    validateImportKey(data[KEY_PARAMETERS], keyFmt);
    byte[] scratchPad = apdu.getBuffer();
    // Step 4 - AES-GCM decrypt the wrapped key
    data[INPUT_DATA] = KMArray.get(cmd, (short) 2);
    data[AUTH_TAG] = KMArray.get(cmd, (short) 3);
    data[NONCE] = KMArray.get(cmd, (short) 4);
    data[AUTH_DATA] = KMArray.get(cmd, (short) 5);

    if (!isValidWrappingKey()) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    data[IMPORTED_KEY_BLOB] = aesGCMDecrypt(getWrappingKey(), data[INPUT_DATA], data[NONCE],
        data[AUTH_DATA], data[AUTH_TAG], scratchPad);
    resetWrappingKey();
    // Step 5 - Import decrypted key
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    // create key blob array
    importKey(apdu, keyFmt, scratchPad);
  }

  //TODO remove hwParameters when this is refactored.
  private KMAttestationCert makeAttestationCert(short attKeyBlob, short attKeyParam,
      short attChallenge, short issuer, short hwParameters, short swParameters, short keyParams,
      byte[] scratchPad) {
    KMAttestationCert cert = makeCommonCert(swParameters, hwParameters,
        keyParams, scratchPad, seProvider);

    short subject = KMKeyParameters.findTag(keyParams, KMType.BYTES_TAG,
        KMType.CERTIFICATE_SUBJECT_NAME);

    // If no subject name is specified then use the default subject name.
    if (subject == KMType.INVALID_VALUE || KMByteTag.length(subject) == 0) {
      subject = KMByteBlob.instance(defaultSubject, (short) 0, (short) defaultSubject.length);
    } else {
      subject = KMByteTag.getValue(subject);
    }
    cert.subjectName(subject);

    // App Id and App Data,
    short appId = KMType.INVALID_VALUE;
    short appData = KMType.INVALID_VALUE;
    if (attKeyParam != KMType.INVALID_VALUE) {
      appId =
          KMKeyParameters.findTag(attKeyParam, KMType.BYTES_TAG, KMType.APPLICATION_ID);
      if (appId != KMTag.INVALID_VALUE) {
        appId = KMByteTag.getValue(appId);
      }
      appData =
          KMKeyParameters.findTag(attKeyParam, KMType.BYTES_TAG, KMType.APPLICATION_DATA);
      if (appData != KMTag.INVALID_VALUE) {
        appData = KMByteTag.getValue(appData);
      }
    }
    //TODO remove following line
    short origBlob = data[KEY_BLOB];
    short pubKey = data[PUB_KEY];
    short keyBlob = parseEncryptedKeyBlob(attKeyBlob, appId, appData, scratchPad);
    short attestationKeySecret = KMArray.get(keyBlob, KEY_BLOB_SECRET);
    short attestParam = KMArray.get(keyBlob, KEY_BLOB_PARAMS);
    attestParam = KMKeyCharacteristics.getStrongboxEnforced(attestParam);
    short attKeyPurpose =
        KMKeyParameters.findTag(attestParam, KMType.ENUM_ARRAY_TAG, KMType.PURPOSE);
    // If the attest key's purpose is not "attest key" then error.
    if (!KMEnumArrayTag.contains(attKeyPurpose, KMType.ATTEST_KEY)) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    // If issuer is not present then it is an error
    if (KMByteBlob.length(issuer) <= 0) {
      KMException.throwIt(KMError.MISSING_ISSUER_SUBJECT_NAME);
    }
    short alg = KMKeyParameters.findTag(attestParam, KMType.ENUM_TAG, KMType.ALGORITHM);

    if (KMEnumTag.getValue(alg) == KMType.RSA) {
      short attestationKeyPublic = KMArray.get(keyBlob, KEY_BLOB_PUB_KEY);
      cert.rsaAttestKey(attestationKeySecret, attestationKeyPublic, KMType.ATTESTATION_CERT);
    } else {
      cert.ecAttestKey(attestationKeySecret, KMType.ATTESTATION_CERT);
    }
    cert.attestationChallenge(attChallenge);
    cert.issuer(issuer);
    //TODO remove following line
    data[PUB_KEY] = pubKey;
    cert.publicKey(data[PUB_KEY]);

    // Save attestation application id - must be present.
    short attAppId =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
            KMType.ATTESTATION_APPLICATION_ID);
    if (attAppId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    cert.extensionTag(attAppId, false);
    // unique id byte blob - uses application id and temporal month count of creation time.
    setUniqueId(cert, scratchPad);
    // Add Attestation Ids if present
    addAttestationIds(cert, scratchPad);

    // Add Tags
    addTags(hwParameters, true, cert);
    addTags(swParameters, false, cert);
    // Add Device Boot locked status
    cert.deviceLocked(bootParamsProv.isDeviceBootLocked());
    // VB data
    cert.verifiedBootHash(getVerifiedBootHash(scratchPad));
    cert.verifiedBootKey(getBootKey(scratchPad));
    cert.verifiedBootState((byte) bootParamsProv.getBootState());

    //TODO remove the following line
    makeKeyCharacteristics(scratchPad);
    data[KEY_BLOB] = origBlob;
    return cert;
  }

  private KMAttestationCert makeCertWithFactoryProvisionedKey(short attChallenge,
      byte[] scratchPad) {
    KMAttestationCert cert = makeCommonCert(data[SW_PARAMETERS], data[HW_PARAMETERS],
        data[KEY_PARAMETERS], scratchPad, seProvider);
    cert.attestationChallenge(attChallenge);
    cert.publicKey(data[PUB_KEY]);
    cert.factoryAttestKey(storeDataInst.getAttestationKey(),
        KMType.FACTORY_PROVISIONED_ATTEST_CERT);

    // Save attestation application id - must be present.
    short attAppId =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
            KMType.ATTESTATION_APPLICATION_ID);
    if (attAppId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    cert.extensionTag(attAppId, false);
    // unique id byte blob - uses application id and temporal month count of creation time.
    setUniqueId(cert, scratchPad);
    // Add Attestation Ids if present
    addAttestationIds(cert, scratchPad);

    // Add Tags
    addTags(data[HW_PARAMETERS], true, cert);
    addTags(data[SW_PARAMETERS], false, cert);
    // Add Device Boot locked status
    cert.deviceLocked(bootParamsProv.isDeviceBootLocked());
    // VB data
    cert.verifiedBootHash(getVerifiedBootHash(scratchPad));
    cert.verifiedBootKey(getBootKey(scratchPad));
    cert.verifiedBootState((byte) bootParamsProv.getBootState());

    //TODO remove the following line
    //makeKeyCharacteristics(scratchPad);
    //data[KEY_BLOB] = origBlob;
    return cert;
  }

  private KMAttestationCert makeSelfSignedCert(short attPrivKey, short attPubKey,
      byte[] scratchPad) {
    //KMAttestationCert cert = makeCommonCert(scratchPad);
    KMAttestationCert cert =
        makeCommonCert(data[SW_PARAMETERS], data[HW_PARAMETERS],
            data[KEY_PARAMETERS], scratchPad, seProvider);
    short alg = KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM);
    byte mode = KMType.FAKE_CERT;
    if (attPrivKey != KMType.INVALID_VALUE) {
      mode = KMType.SELF_SIGNED_CERT;
    }
    short subject = KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
        KMType.CERTIFICATE_SUBJECT_NAME);
    // If no subject name is specified then use the default subject name.
    if (subject == KMType.INVALID_VALUE || KMByteTag.length(subject) == 0) {
      subject = KMByteBlob.instance(defaultSubject, (short) 0, (short) defaultSubject.length);
    } else {
      subject = KMByteTag.getValue(subject);
    }

    if (KMEnumTag.getValue(alg) == KMType.RSA) {
      cert.rsaAttestKey(attPrivKey, attPubKey, mode);
    } else {
      cert.ecAttestKey(attPrivKey, mode);
    }
    cert.issuer(subject);
    cert.subjectName(subject);
    cert.publicKey(attPubKey);
    return cert;
  }

  protected short getBootKey(byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, VERIFIED_BOOT_KEY_SIZE, (byte) 0);
    short len = bootParamsProv.getBootKey(scratchPad, (short) 0);
    if (len != VERIFIED_BOOT_KEY_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMByteBlob.instance(scratchPad, (short) 0, VERIFIED_BOOT_KEY_SIZE);
  }

  protected short getVerifiedBootHash(byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, VERIFIED_BOOT_HASH_SIZE, (byte) 0);
    short len = bootParamsProv.getVerifiedBootHash(scratchPad, (short) 0);
    if (len != VERIFIED_BOOT_HASH_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMByteBlob.instance(scratchPad, (short) 0, VERIFIED_BOOT_HASH_SIZE);
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

  // --------------------------------
  // Only add the Attestation ids which are requested in the attestation parameters.
  // If the requested attestation ids are not provisioned or deleted then
  // throw CANNOT_ATTEST_IDS error. If there is mismatch in the attestation
  // id values of both the requested parameters and the provisioned parameters
  // then throw INVALID_TAG error.
  private void addAttestationIds(KMAttestationCert cert, byte[] scratchPad) {
    byte index = 0;
    short attIdTag;
    short attIdTagValue;
    short storedAttIdLen;
    while (index < (short) ATTEST_ID_TAGS.length) {
      attIdTag = KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
          ATTEST_ID_TAGS[index]);
      if (attIdTag != KMType.INVALID_VALUE) {
        attIdTagValue = KMByteTag.getValue(attIdTag);
        storedAttIdLen = storeDataInst.getData((byte) mapAttestIdToStoreId(ATTEST_ID_TAGS[index]),
            scratchPad, (short) 0);
        // Return CANNOT_ATTEST_IDS if Attestation IDs are not provisioned or
        // Attestation IDs are deleted.
        if (storedAttIdLen == 0) {
          KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
        }
        // Return INVALID_TAG if Attestation IDs does not match.
        if ((storedAttIdLen != KMByteBlob.length(attIdTagValue)) ||
            (0 != Util.arrayCompare(scratchPad, (short) 0,
                KMByteBlob.getBuffer(attIdTagValue),
                KMByteBlob.getStartOff(attIdTagValue),
                storedAttIdLen))) {
          KMException.throwIt(KMError.INVALID_TAG);
        }
        short blob = KMByteBlob.instance(scratchPad, (short) 0, storedAttIdLen);
        cert.extensionTag(KMByteTag.instance(ATTEST_ID_TAGS[index], blob), true);
      }
      index++;
    }
  }

  private void addTags(short params, boolean hwEnforced, KMAttestationCert cert) {
    short index = 0;
    short arr = KMKeyParameters.getVals(params);
    short len = KMArray.length(arr);
    short tag;
    while (index < len) {
      tag = KMArray.get(arr, index);
      cert.extensionTag(tag, hwEnforced);
      index++;
    }
  }

  private void setUniqueId(KMAttestationCert cert, byte[] scratchPad) {
    if (!KMTag.isPresent(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.INCLUDE_UNIQUE_ID)) {
      return;
    }
    // temporal count T
    short time = KMKeyParameters.findTag(data[SW_PARAMETERS], KMType.DATE_TAG,
        KMType.CREATION_DATETIME);
    if (time == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    time = KMIntegerTag.getValue(time);

    // Application Id C
    short appId = KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
        KMType.ATTESTATION_APPLICATION_ID);
    if (appId == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    appId = KMByteTag.getValue(appId);

    // Reset After Rotation R - it will be part of HW Enforced key
    // characteristics
    byte resetAfterRotation = 0;
    if (KMTag.isPresent(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.RESET_SINCE_ID_ROTATION)) {
      resetAfterRotation = 0x01;
    }

    cert.makeUniqueId(scratchPad, (short) 0, KMInteger.getBuffer(time),
        KMInteger.getStartOff(time), KMInteger.length(time),
        KMByteBlob.getBuffer(appId), KMByteBlob.getStartOff(appId), KMByteBlob.length(appId),
        resetAfterRotation,
        storeDataInst.getMasterKey());
  }

  private void deleteAttestationIds() {
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_BRAND);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_DEVICE);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_IMEI);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_MEID);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_MANUFACTURER);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_PRODUCT);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_MODEL);
    storeDataInst.clearData(KMDataStoreConstants.ATT_ID_SERIAL);
  }

  private void processDestroyAttIdsCmd(APDU apdu) {
    deleteAttestationIds();
    sendError(apdu, KMError.OK);
  }

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private short abortOperationCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, KMInteger.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processAbortOperationCmd(APDU apdu) {
    short cmd = abortOperationCmd(apdu);
    data[OP_HANDLE] = KMArray.get(cmd, (short) 0);
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      sendError(apdu, KMError.INVALID_OPERATION_HANDLE);
    } else {
      releaseOperation(op);
      sendError(apdu, KMError.OK);
    }
  }

  private short finishOperationCmd(APDU apdu) {
    return receiveIncoming(apdu, prepareFinishExp());
  }

  private void processFinishOperationCmd(APDU apdu) {
    short cmd = finishOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    getFinishInputParameters(cmd, data, OP_HANDLE, KEY_PARAMETERS, INPUT_DATA,
        SIGNATURE, HW_TOKEN, VERIFICATION_TOKEN, CONFIRMATION_TOKEN);

    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // Authorize the finish operation
    authorizeUpdateFinishOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
        finishTrustedConfirmationOperation(op);
      case KMType.VERIFY:
        finishSigningVerifyingOperation(op, scratchPad);
        break;
      case KMType.ENCRYPT:
        finishEncryptOperation(op, scratchPad);
        break;
      case KMType.DECRYPT:
        finishDecryptOperation(op, scratchPad);
        break;
      case KMType.AGREE_KEY:
        finishKeyAgreementOperation(op, scratchPad);
        break;
    }
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    // Remove the operation handle
    releaseOperation(op);

    // make response
    sendOutgoing(apdu, prepareFinishResp(data[OUTPUT_DATA]));
  }

  private void finishEncryptOperation(KMOperationState op, byte[] scratchPad) {
    if (op.getAlgorithm() != KMType.AES && op.getAlgorithm() != KMType.DES) {
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    finishAesDesOperation(op);
  }

  private void finishDecryptOperation(KMOperationState op, byte[] scratchPad) {
    short len = KMByteBlob.length(data[INPUT_DATA]);
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // Fill the scratch pad with zero
        Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
        if (op.getPadding() == KMType.PADDING_NONE && len != 256) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
        len =
            op.getOperation().finish(
                KMByteBlob.getBuffer(data[INPUT_DATA]), KMByteBlob.getStartOff(data[INPUT_DATA]),
                len, scratchPad, (short) 0);

        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, len);
        break;
      case KMType.AES:
      case KMType.DES:
        finishAesDesOperation(op);
        break;
    }
  }

  private void finishAesDesOperation(KMOperationState op) {
    short len = KMByteBlob.length(data[INPUT_DATA]);
    short blockSize = AES_BLOCK_SIZE;
    if (op.getAlgorithm() == KMType.DES) {
      blockSize = DES_BLOCK_SIZE;
    }

    if (op.getPurpose() == KMType.DECRYPT && len > 0
        && (op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC)
        && ((short) (len % blockSize) != 0)) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    if (op.getBlockMode() == KMType.GCM) {
      if (op.getPurpose() == KMType.DECRYPT && (len < (short) (op.getMacLength() / 8))) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
      // update aad if there is any
      updateAAD(op, (byte) 0x01);
      if (op.isAesGcmUpdateAllowed()) {
        op.setAesGcmUpdateComplete();
      }
      // Get the output size
      len = op.getOperation().getAESGCMOutputSize(len, (short) (op.getMacLength() / 8));
    }
    // If padding i.e. pkcs7 then add padding to right
    // Output data can at most one block size more the input data in case of pkcs7 encryption
    // In case of gcm we will allocate extra memory of the size equal to blocksize.
    data[OUTPUT_DATA] = KMByteBlob.instance((short) (len + 2 * blockSize));
    try {
      len = op.getOperation().finish(
          KMByteBlob.getBuffer(data[INPUT_DATA]),
          KMByteBlob.getStartOff(data[INPUT_DATA]),
          KMByteBlob.length(data[INPUT_DATA]),
          KMByteBlob.getBuffer(data[OUTPUT_DATA]),
          KMByteBlob.getStartOff(data[OUTPUT_DATA]));
    } catch (CryptoException e) {
      if (e.getReason() == CryptoException.ILLEGAL_USE) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
    }
    KMByteBlob.setLength(data[OUTPUT_DATA], len);
  }

  public void finishKeyAgreementOperation(KMOperationState op, byte[] scratchPad) {
    KMException.throwIt(KMError.UNIMPLEMENTED);
  }

  private void finishSigningVerifyingOperation(KMOperationState op, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // If there is no padding we can treat signing as a RSA decryption operation.
        try {
          if (op.getPurpose() == KMType.SIGN) {
            // len of signature will be 256 bytes - but it can be less then 256 bytes
            short len = op.getOperation().sign(
                KMByteBlob.getBuffer(data[INPUT_DATA]),
                KMByteBlob.getStartOff(data[INPUT_DATA]),
                KMByteBlob.length(data[INPUT_DATA]), scratchPad,
                (short) 0);
            // Maximum output size of signature is 256 bytes. - the signature will always be positive
            data[OUTPUT_DATA] = KMByteBlob.instance((short) 256);
            Util.arrayCopyNonAtomic(
                scratchPad,
                (short) 0,
                KMByteBlob.getBuffer(data[OUTPUT_DATA]),
                (short) (KMByteBlob.getStartOff(data[OUTPUT_DATA]) + 256 - len),
                len);
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException e) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        break;
      case KMType.EC:
        short len = KMByteBlob.length(data[INPUT_DATA]);
        // If DIGEST NONE then truncate the input data to 32 bytes.
        if (op.getDigest() == KMType.DIGEST_NONE && len > 32) {
          len = 32;
        }
        if (op.getPurpose() == KMType.SIGN) {
          // len of signature will be 512 bits i.e. 64 bytes
          len =
              op.getOperation()
                  .sign(
                      KMByteBlob.getBuffer(data[INPUT_DATA]),
                      KMByteBlob.getStartOff(data[INPUT_DATA]),
                      len,
                      scratchPad,
                      (short) 0);
          data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, len);
        } else {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.HMAC:
        // As per Keymaster HAL documentation, the length of the Hmac output can
        // be decided by using TAG_MAC_LENGTH in Keyparameters. But there is no
        // such provision to control the length of the Hmac output using JavaCard
        // crypto APIs and the current implementation always returns 32 bytes
        // length of Hmac output. So to provide support to TAG_MAC_LENGTH
        // feature, we truncate the output signature to TAG_MAC_LENGTH and return
        // the truncated signature back to the caller. At the time of verfication
        // we again compute the signature of the plain text input, truncate it to
        // TAG_MAC_LENGTH and compare it with the input signature for
        // verification. So this is the reason we are using KMType.SIGN directly
        // instead of using op.getPurpose().
        op.getOperation()
            .sign(
                KMByteBlob.getBuffer(data[INPUT_DATA]),
                KMByteBlob.getStartOff(data[INPUT_DATA]),
                KMByteBlob.length(data[INPUT_DATA]),
                scratchPad,
                (short) 0);
        if (op.getPurpose() == KMType.SIGN) {
          // Copy only signature of mac length size.
          data[OUTPUT_DATA] =
              KMByteBlob.instance(scratchPad, (short) 0, (short) (op.getMacLength() / 8));
        } else if (op.getPurpose() == KMType.VERIFY) {
          if (0
              != Util.arrayCompare(
              scratchPad, (short) 0,
              KMByteBlob.getBuffer(data[SIGNATURE]),
              KMByteBlob.getStartOff(data[SIGNATURE]),
              KMByteBlob.length(data[SIGNATURE]))) {
            KMException.throwIt(KMError.VERIFICATION_FAILED);
          }
          data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
        }
        break;
      default: // This is should never happen
        KMException.throwIt(KMError.OPERATION_CANCELLED);
        break;
    }
  }

  private void authorizeUpdateFinishOperation(KMOperationState op, byte[] scratchPad) {
    // If one time user Authentication is required
    if (op.isSecureUserIdReqd() && !op.isAuthTimeoutValidated()) {
      // Validate Verification Token.
      validateVerificationToken(data[VERIFICATION_TOKEN], scratchPad);
      // validate operation handle.
      short ptr = KMVerificationToken.getChallenge(data[VERIFICATION_TOKEN]);
      if (KMInteger.compare(ptr, op.getHandle()) != 0) {
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
      tmpVariables[0] = op.getAuthTime();
      tmpVariables[2] = KMVerificationToken.getTimestamp(data[VERIFICATION_TOKEN]);
      if (tmpVariables[2] == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
      if (KMInteger.compare(tmpVariables[0], tmpVariables[2]) < 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      op.setAuthTimeoutValidated(true);
    } else if (op.isAuthPerOperationReqd()) { // If Auth per operation is required
      tmpVariables[0] = KMHardwareAuthToken.getChallenge(data[HW_TOKEN]);
      if (KMInteger.compare(data[OP_HANDLE], tmpVariables[0]) != 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      if (!authTokenMatches(op.getUserSecureId(), op.getAuthType(), scratchPad)) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
    }
  }

  private void authorizeKeyUsageForCount(byte[] scratchPad) {
    // Allocate first 12 bytes in scratchpad required for integer
    // operations.
    short scratchPadOff = 0;
    short requiredScratchBufLen = 12;
    Util.arrayFillNonAtomic(scratchPad, scratchPadOff, requiredScratchBufLen, (byte) 0);

    short usageLimitBufLen = KMIntegerTag.getValue(scratchPad, scratchPadOff,
        KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT, data[HW_PARAMETERS]);

    if (usageLimitBufLen == KMType.INVALID_VALUE) {
      return;
    }

    if (usageLimitBufLen > 4) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    if (storeDataInst.isAuthTagPersisted(KMByteBlob.getBuffer(data[AUTH_TAG]),
        KMByteBlob.getStartOff(data[AUTH_TAG]),
        KMByteBlob.length(data[AUTH_TAG]), scratchPad, requiredScratchBufLen)) {
      // Get current counter, update and increment it.
      short len = storeDataInst
          .getRateLimitedKeyCount(KMByteBlob.getBuffer(data[AUTH_TAG]),
              KMByteBlob.getStartOff(data[AUTH_TAG]),
              KMByteBlob.length(data[AUTH_TAG]), scratchPad, (short) (scratchPadOff + 4));
      if (len != 4) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      if (0 >= KMInteger.unsignedByteArrayCompare(scratchPad, scratchPadOff, scratchPad,
          (short) (scratchPadOff + 4), (short) 4)) {
        KMException.throwIt(KMError.KEY_MAX_OPS_EXCEEDED);
      }
      // Increment the counter.
      Util.arrayFillNonAtomic(scratchPad, scratchPadOff, len, (byte) 0);
      Util.setShort(scratchPad, (short) (scratchPadOff + 2), (short) 1);
      KMUtils.add(scratchPad, scratchPadOff, (short) (scratchPadOff + len),
          (short) (scratchPadOff + len * 2));

      storeDataInst.setRateLimitedKeyCount(KMByteBlob.getBuffer(data[AUTH_TAG]),
          KMByteBlob.getStartOff(data[AUTH_TAG]),
          KMByteBlob.length(data[AUTH_TAG]),
          scratchPad, (short) (scratchPadOff + len * 2), len, scratchPad,
          requiredScratchBufLen);
    } else {
      // Persist auth tag.
      if (!storeDataInst.storeAuthTag(KMByteBlob.getBuffer(data[AUTH_TAG]),
          KMByteBlob.getStartOff(data[AUTH_TAG]),
          KMByteBlob.length(data[AUTH_TAG]), scratchPad, scratchPadOff)) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
      }
    }
  }

  private void authorizeDeviceUnlock(byte[] scratchPad) {
    // If device is locked and key characteristics requires unlocked device then check whether
    // HW auth token has correct timestamp.
    short ptr =
        KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.BOOL_TAG,
            KMType.UNLOCKED_DEVICE_REQUIRED);

    if (ptr != KMType.INVALID_VALUE && readBoolean(KMDataStoreConstants.DEVICE_LOCKED, scratchPad,
        (short) 0)) {
      if (!validateHwToken(data[HW_TOKEN], scratchPad)) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      ptr = KMHardwareAuthToken.getTimestamp(data[HW_TOKEN]);
      // Check if the current auth time stamp is greater than device locked time stamp
      short ts = readInteger64(KMDataStoreConstants.DEVICE_LOCKED_TIME, scratchPad, (short) 0);
      if (KMInteger.compare(ptr, ts) <= 0) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      // Now check if the device unlock requires password only authentication and whether
      // auth token is generated through password authentication or not.
      if (readBoolean(KMDataStoreConstants.DEVICE_LOCKED_PASSWORD_ONLY, scratchPad, (short) 0)) {
        ptr = KMHardwareAuthToken.getHwAuthenticatorType(data[HW_TOKEN]);
        ptr = KMEnum.getVal(ptr);
        if (((byte) ptr & KMType.PASSWORD) == 0) {
          KMException.throwIt(KMError.DEVICE_LOCKED);
        }
      }
      // Unlock the device
      // repository.deviceLockedFlag = false;
      writeBoolean(KMDataStoreConstants.DEVICE_LOCKED, false);
      storeDataInst.clearData(KMDataStoreConstants.DEVICE_LOCKED_TIME);
    }
  }

  private boolean verifyVerificationTokenMacInBigEndian(short verToken, byte[] scratchPad) {
    // concatenation length will be 37 + length of verified parameters list - which
    // is typically empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopyNonAtomic(authVerification, (short) 0, scratchPad, (short) 0,
        (short) authVerification.length);
    short len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.getChallenge(verToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.getTimestamp(verToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;
    // concatenate security level - 4 bytes
    scratchPad[(short) (len + 3)] = TRUSTED_ENVIRONMENT;
    len += 4;
    // hmac the data
    ptr = getMacFromVerificationToken(verToken);

    return seProvider.hmacVerify(
        storeDataInst.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.getBuffer(ptr),
        KMByteBlob.getStartOff(ptr),
        KMByteBlob.length(ptr));
  }

  private void validateVerificationToken(short verToken, byte[] scratchPad) {
    short ptr = getMacFromVerificationToken(verToken);
    // If mac length is zero then token is empty.
    if (KMByteBlob.length(ptr) == 0) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    if (!verifyVerificationTokenMacInBigEndian(verToken, scratchPad)) {
      // Throw Exception if none of the combination works.
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private short updateOperationCmd(APDU apdu) {
    return receiveIncoming(apdu, prepareUpdateExp());
  }

  private void processUpdateOperationCmd(APDU apdu) {
    short cmd = updateOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    getUpdateInputParameters(cmd, data, OP_HANDLE, KEY_PARAMETERS,
        INPUT_DATA, HW_TOKEN, VERIFICATION_TOKEN);

    // Input data must be present even if it is zero length.
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    // Check Operation Handle and get op state
    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);
    short inputConsumed = 0;
    if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
      // update the data.
      op.getOperation()
          .update(
              KMByteBlob.getBuffer(data[INPUT_DATA]),
              KMByteBlob.getStartOff(data[INPUT_DATA]),
              KMByteBlob.length(data[INPUT_DATA]));
      // update trusted confirmation operation
      updateTrustedConfirmationOperation(op);

      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    } else if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
      // Update for encrypt/decrypt using RSA will not be supported because to do this op state
      //  will have to buffer the data - so reject the update if it is rsa algorithm.
      if (op.getAlgorithm() == KMType.RSA) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      short len = KMByteBlob.length(data[INPUT_DATA]);
      short blockSize = DES_BLOCK_SIZE;
      if (op.getAlgorithm() == KMType.AES) {
        blockSize = AES_BLOCK_SIZE;
        if (op.getBlockMode() == KMType.GCM) {
          // data[KEY_PARAMETERS] will be invalid for keymint
          if (data[KEY_PARAMETERS] != KMType.INVALID_VALUE) {
            updateAAD(op, (byte) 0x00);
          }
          // if input data present
          if (len > 0) {
            // no more future updateAAD allowed if input data present.
            if (op.isAesGcmUpdateAllowed()) {
              op.setAesGcmUpdateComplete();
            }
          }
        }
      }
      // Allocate output buffer as input data is already block aligned
      data[OUTPUT_DATA] = KMByteBlob.instance((short) (len + 2 * blockSize));
      // Otherwise just update the data.
      // HAL consumes all the input and maintains a buffered data inside it. So the
      // applet sends the inputConsumed length as same as the input length.
      inputConsumed = len;
      try {
        len =
            op.getOperation()
                .update(
                    KMByteBlob.getBuffer(data[INPUT_DATA]),
                    KMByteBlob.getStartOff(data[INPUT_DATA]),
                    KMByteBlob.length(data[INPUT_DATA]),
                    KMByteBlob.getBuffer(data[OUTPUT_DATA]),
                    KMByteBlob.getStartOff(data[OUTPUT_DATA]));
      } catch (CryptoException e) {
        KMException.throwIt(KMError.INVALID_TAG);
      }

      // Adjust the Output data if it is not equal to input data.
      // This happens in case of JCardSim provider.
      KMByteBlob.setLength(data[OUTPUT_DATA], len);
    }

    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    // Persist if there are any updates.
    // make response
    sendOutgoing(apdu, prepareUpdateResp(data[OUTPUT_DATA], KMInteger.uint_16(inputConsumed)));
  }

  private short updateAadOperationCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 4);
    KMArray.add(cmd, (short) 0, KMInteger.exp());
    KMArray.add(cmd, (short) 1, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 2, authToken);
    short verToken = getKMVerificationTokenExp();
    KMArray.add(cmd, (short) 3, verToken);
    return receiveIncoming(apdu, cmd);
  }

  //update operation should send 0x00 for finish variable, where as finish operation
  // should send 0x01 for finish variable.
  public void updateAAD(KMOperationState op, byte finish) {
    // Is input data absent
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Update can be called either to update auth data, update input data or both.
    // But if it is called for neither then return error.
    short len = KMByteBlob.length(data[INPUT_DATA]);
    short tag =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.ASSOCIATED_DATA);
    // For Finish operation the input data can be zero length and associated data can be
    // INVALID_VALUE
    // For update operation either input data or associated data should be present.
    if (tag == KMType.INVALID_VALUE && len <= 0 && finish == 0x00) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    // Check if associated data is present and update aad still allowed by the operation.
    if (tag != KMType.INVALID_VALUE) {
      // If allowed the update the aad
      if (!op.isAesGcmUpdateAllowed()) {
        KMException.throwIt(KMError.INVALID_TAG);
      }
      // If allowed the update the aad
      short aData = KMByteTag.getValue(tag);

      op.getOperation()
          .updateAAD(
              KMByteBlob.getBuffer(aData),
              KMByteBlob.getStartOff(aData),
              KMByteBlob.length(aData));
    }
  }

  private void processUpdateAadOperationCmd(APDU apdu) {
    short cmd = updateAadOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[OP_HANDLE] = KMArray.get(cmd, (short) 0);
    data[INPUT_DATA] = KMArray.get(cmd, (short) 1);
    data[HW_TOKEN] = KMArray.get(cmd, (short) 2);
    data[VERIFICATION_TOKEN] = KMArray.get(cmd, (short) 3);

    // Input data must be present even if it is zero length.
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Check Operation Handle and get op state
    // Check Operation Handle
    KMOperationState op = findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    if (op.getAlgorithm() != KMType.AES) {
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    if (op.getBlockMode() != KMType.GCM) {
      KMException.throwIt(KMError.INCOMPATIBLE_BLOCK_MODE);
    }
    if (!op.isAesGcmUpdateAllowed()) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    if (op.getPurpose() != KMType.ENCRYPT && op.getPurpose() != KMType.DECRYPT) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);
    try {
      op.getOperation()
          .updateAAD(
              KMByteBlob.getBuffer(data[INPUT_DATA]),
              KMByteBlob.getStartOff(data[INPUT_DATA]),
              KMByteBlob.length(data[INPUT_DATA]));
    } catch (CryptoException exp) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }

    // make response
    short resp = KMArray.instance((short) 1);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    sendOutgoing(apdu, resp);
  }

  private short beginOperationCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 4);
    // Arguments
    short params = KMKeyParameters.expAny();
    KMArray.add(cmd, (short) 0, KMEnum.instance(KMType.PURPOSE));
    KMArray.add(cmd, (short) 1, KMByteBlob.exp());
    KMArray.add(cmd, (short) 2, params);
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 3, authToken);
    return receiveIncoming(apdu, cmd);
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = beginOperationCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short purpose = KMArray.get(cmd, (short) 0);
    data[KEY_BLOB] = KMArray.get(cmd, (short) 1);
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 2);
    data[HW_TOKEN] = KMArray.get(cmd, (short) 3);
    purpose = KMEnum.getVal(purpose);
    // Check for app id and app data.
    data[APP_ID] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_ID);
    data[APP_DATA] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_DATA);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.getValue(data[APP_ID]);
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.getValue(data[APP_DATA]);
    }
    // Parse the encrypted blob and decrypt it.
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    KMTag.assertPresence(data[SB_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM,
        KMError.UNSUPPORTED_ALGORITHM);
    short algorithm = KMEnumTag.getValue(KMType.ALGORITHM, data[SB_PARAMETERS]);

    //TODO should be removed for keymint
    // If Blob usage tag is present in key characteristics then it should be standalone.
    if (KMTag.isPresent(data[SB_PARAMETERS], KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ)) {
      if (KMEnumTag.getValue(KMType.BLOB_USAGE_REQ, data[SB_PARAMETERS]) != KMType.STANDALONE) {
        KMException.throwIt(KMError.UNSUPPORTED_TAG);
      }
    }

    // Generate a random number for operation handle
    short buf = KMByteBlob.instance(KMOperationState.OPERATION_HANDLE_SIZE);
    generateUniqueOperationHandle(
        KMByteBlob.getBuffer(buf),
        KMByteBlob.getStartOff(buf),
        KMByteBlob.length(buf));
    /* opHandle is a KMInteger and is encoded as KMInteger when it is returned back. */
    short opHandle = KMInteger.instance(
        KMByteBlob.getBuffer(buf),
        KMByteBlob.getStartOff(buf),
        KMByteBlob.length(buf));
    KMOperationState op = reserveOperation(algorithm, opHandle);
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    data[OP_HANDLE] = op.getHandle();
    op.setPurpose((byte) purpose);
    op.setKeySize(KMByteBlob.length(data[SECRET]));
    authorizeAndBeginOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
        beginTrustedConfirmationOperation(op);
      case KMType.VERIFY:
        beginSignVerifyOperation(op);
        break;
      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        beginCipherOperation(op);
        break;
      case KMType.AGREE_KEY:
        beginKeyAgreementOperation(op);
        break;
      default:
        KMException.throwIt(KMError.UNIMPLEMENTED);
        break;
    }
    short iv = KMType.INVALID_VALUE;
    // If the data[IV] is required to be returned.
    // As per VTS, for the decryption operation don't send the iv back.
    if (data[IV] != KMType.INVALID_VALUE
        && op.getPurpose() != KMType.DECRYPT
        && op.getBlockMode() != KMType.ECB) {
      iv = KMArray.instance((short) 1);
      if (op.getAlgorithm() == KMType.DES && op.getBlockMode() == KMType.CBC) {
        // For AES/DES we are generate an random iv of length 16 bytes.
        // While sending the iv back for DES/CBC mode of opeation only send
        // 8 bytes back.
        short ivBlob = KMByteBlob.instance((short) 8);
        Util.arrayCopy(
            KMByteBlob.getBuffer(data[IV]),
            KMByteBlob.getStartOff(data[IV]),
            KMByteBlob.getBuffer(ivBlob),
            KMByteBlob.getStartOff(ivBlob),
            (short) 8);
        data[IV] = ivBlob;
      }
      KMArray.add(iv, (short) 0, KMByteTag.instance(KMType.NONCE, data[IV]));
    } else {
      iv = KMArray.instance((short) 0);
    }

    short params = KMKeyParameters.instance(iv);
    short resp = prepareBeginResp(params, data[OP_HANDLE], KMInteger.uint_8(op.getBufferingMode()),
        KMInteger.uint_16((short) (op.getMacLength() / 8)));
    sendOutgoing(apdu, resp);
  }

  private void authorizePurpose(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.AES:
      case KMType.DES:
        if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY ||
            op.getPurpose() == KMType.AGREE_KEY) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.EC:
        if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.HMAC:
        if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT ||
            op.getPurpose() == KMType.AGREE_KEY) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.RSA:
        if (op.getPurpose() == KMType.AGREE_KEY) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      default:
        break;
    }
    if (!KMEnumArrayTag.contains(KMType.PURPOSE, op.getPurpose(), data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
    }
  }

  private void authorizeDigest(KMOperationState op) {
    short digests =
        KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.DIGEST);
    op.setDigest(KMType.DIGEST_NONE);
    short param =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.DIGEST);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(param) != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
      }
      param = KMEnumArrayTag.get(param, (short) 0);
      if (!KMEnumArrayTag.contains(digests, param)) {
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      }
      op.setDigest((byte) param);
    } else if (KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_PKCS1_1_5_SIGN,
        data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    short paramPadding =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.PADDING);
    if (paramPadding != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(paramPadding) != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
      }
      paramPadding = KMEnumArrayTag.get(paramPadding, (short) 0);
    }
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        if ((paramPadding == KMType.RSA_OAEP || paramPadding == KMType.RSA_PSS)
            && param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
        }
        break;
      case KMType.EC:
      case KMType.HMAC:
        if (op.getPurpose() != KMType.AGREE_KEY && param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
        }
        break;
      default:
        break;
    }
  }

  private void authorizePadding(KMOperationState op) {
    short paddings =
        KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.PADDING);
    op.setPadding(KMType.PADDING_NONE);
    short param =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.PADDING);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(param) != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
      }
      param = KMEnumArrayTag.get(param, (short) 0);
      if (!KMEnumArrayTag.contains(paddings, param)) {
        KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
      }
    }
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        if ((op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY)
            && param != KMType.PADDING_NONE
            && param != KMType.RSA_PSS
            && param != KMType.RSA_PKCS1_1_5_SIGN) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        if ((op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT)
            && param != KMType.PADDING_NONE
            && param != KMType.RSA_OAEP
            && param != KMType.RSA_PKCS1_1_5_ENCRYPT) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }

        if (param == KMType.PADDING_NONE && op.getDigest() != KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if ((param == KMType.RSA_OAEP || param == KMType.RSA_PSS)
            && op.getDigest() == KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if (param == KMType.RSA_OAEP) {
          op.setMgfDigest(
              (byte) getMgf1Digest(data[KEY_PARAMETERS], data[HW_PARAMETERS]));
        }
        op.setPadding((byte) param);
        break;
      case KMType.DES:
      case KMType.AES:
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
        }
        op.setPadding((byte) param);
        break;
      default:
        break;
    }
  }

  private void authorizeBlockModeAndMacLength(KMOperationState op) {
    short param =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.length(param) != 1) {
        KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
      }
      param = KMEnumArrayTag.get(param, (short) 0);
    }
    if (KMType.AES == op.getAlgorithm() || KMType.DES == op.getAlgorithm()) {
      if (!KMEnumArrayTag.contains(KMType.BLOCK_MODE, param, data[HW_PARAMETERS])) {
        KMException.throwIt(KMError.INCOMPATIBLE_BLOCK_MODE);
      }
    }
    short macLen =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MAC_LENGTH, data[KEY_PARAMETERS]);
    switch (op.getAlgorithm()) {
      case KMType.AES:
        //Validate the block mode.
        switch (param) {
          case KMType.ECB:
          case KMType.CBC:
          case KMType.CTR:
          case KMType.GCM:
            break;
          default:
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
        }
        if (param == KMType.GCM) {
          if (op.getPadding() != KMType.PADDING_NONE || op.getPadding() == KMType.PKCS7) {
            KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
          }
          if (macLen == KMType.INVALID_VALUE) {
            KMException.throwIt(KMError.MISSING_MAC_LENGTH);
          }
          if (macLen % 8 != 0
              || macLen > 128
              || macLen
              < KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
            KMException.throwIt(KMError.INVALID_MAC_LENGTH);
          }
          op.setMacLength(macLen);
        }
        if (param == KMType.CTR) {
          if (op.getPadding() != KMType.PADDING_NONE || op.getPadding() == KMType.PKCS7) {
            KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
          }
        }
        break;
      case KMType.DES:
        //Validate the block mode.
        switch (param) {
          case KMType.ECB:
          case KMType.CBC:
            break;
          default:
            KMException.throwIt(KMError.UNSUPPORTED_BLOCK_MODE);
        }
        break;
      case KMType.HMAC:
        if (macLen == KMType.INVALID_VALUE) {
          if (op.getPurpose() == KMType.SIGN) {
            KMException.throwIt(KMError.MISSING_MAC_LENGTH);
          }
        } else {
          // MAC length may not be specified for verify.
          if (op.getPurpose() == KMType.VERIFY) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          }
          if (macLen
              < KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
            KMException.throwIt(KMError.INVALID_MAC_LENGTH);
          } else if (macLen % 8 != 0 || macLen > 256) {
            KMException.throwIt(KMError.UNSUPPORTED_MAC_LENGTH);
          }
          op.setMacLength(macLen);
        }
        break;
      default:
        break;
    }
    op.setBlockMode((byte) param);
  }

  private void authorizeAndBeginOperation(KMOperationState op, byte[] scratchPad) {
    authorizePurpose(op);
    authorizeDigest(op);
    authorizePadding(op);
    authorizeBlockModeAndMacLength(op);
    assertPrivateOperation(op.getPurpose(), op.getAlgorithm());
    authorizeUserSecureIdAuthTimeout(op, scratchPad);
    authorizeDeviceUnlock(scratchPad);
    authorizeKeyUsageForCount(scratchPad);

    //Validate early boot
    validateEarlyBoot(data[HW_PARAMETERS], INS_BEGIN_OPERATION_CMD, scratchPad, (short) 0,
        KMError.INVALID_KEY_BLOB);

    //Validate bootloader only 
    if (readBoolean(KMDataStoreConstants.BOOT_ENDED_STATUS, scratchPad, (short) 0)) {
      KMTag.assertAbsence(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY,
          KMError.INVALID_KEY_BLOB);
    }

    // Authorize Caller Nonce - if caller nonce absent in key char and nonce present in
    // key params then fail if it is not a Decrypt operation
    data[IV] = KMType.INVALID_VALUE;

    if (!KMTag.isPresent(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.CALLER_NONCE)
        && KMTag.isPresent(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.NONCE)
        && op.getPurpose() != KMType.DECRYPT) {
      KMException.throwIt(KMError.CALLER_NONCE_PROHIBITED);
    }

    short nonce = KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.NONCE);
    // If Nonce is present then check whether the size of nonce is correct.
    if (nonce != KMType.INVALID_VALUE) {
      data[IV] = KMByteTag.getValue(nonce);
      // For CBC mode - iv must be 8 bytes
      if (op.getBlockMode() == KMType.CBC
          && op.getAlgorithm() == KMType.DES
          && KMByteBlob.length(data[IV]) != 8) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }

      // For GCM mode - IV must be 12 bytes
      if (KMByteBlob.length(data[IV]) != 12 && op.getBlockMode() == KMType.GCM) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }

      // For AES CBC and CTR modes IV must be 16 bytes
      if ((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.CTR)
          && op.getAlgorithm() == KMType.AES
          && KMByteBlob.length(data[IV]) != 16) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
    } else if (op.getAlgorithm() == KMType.AES || op.getAlgorithm() == KMType.DES) {

      // For symmetric decryption iv is required
      if (op.getPurpose() == KMType.DECRYPT
          && (op.getBlockMode() == KMType.CBC
          || op.getBlockMode() == KMType.GCM
          || op.getBlockMode() == KMType.CTR)) {
        KMException.throwIt(KMError.MISSING_NONCE);
      } else if (op.getBlockMode() == KMType.ECB) {
        // For ECB we create zero length nonce
        data[IV] = KMByteBlob.instance((short) 0);
      } else if (op.getPurpose() == KMType.ENCRYPT) {

        // For encrypt mode if nonce is absent then create random nonce of correct length
        byte ivLen = 16;
        if (op.getBlockMode() == KMType.GCM) {
          ivLen = 12;
        } else if (op.getAlgorithm() == KMType.DES) {
          ivLen = 8;
        }
        data[IV] = KMByteBlob.instance(ivLen);
        seProvider.newRandomNumber(
            KMByteBlob.getBuffer(data[IV]),
            KMByteBlob.getStartOff(data[IV]),
            KMByteBlob.length(data[IV]));
      }
    }
  }

  public void beginKeyAgreementOperation(KMOperationState op) {
    KMException.throwIt(KMError.UNIMPLEMENTED);
  }

  private void beginCipherOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.DECRYPT) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte) op.getAlgorithm(),
                    (byte) op.getPadding(),
                    (byte) op.getDigest(),
                    (byte) op.getMgfDigest(),
                    KMByteBlob.getBuffer(data[SECRET]),
                    KMByteBlob.getStartOff(data[SECRET]),
                    KMByteBlob.length(data[SECRET]),
                    KMByteBlob.getBuffer(data[PUB_KEY]),
                    KMByteBlob.getStartOff(data[PUB_KEY]),
                    KMByteBlob.length(data[PUB_KEY])));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.AES:
      case KMType.DES:
        if (op.getBlockMode() == KMType.GCM) {
          op.setAesGcmUpdateStart();
        }
        try {
          op.setOperation(
              seProvider.initSymmetricOperation(
                  (byte) op.getPurpose(),
                  (byte) op.getAlgorithm(),
                  (byte) op.getDigest(),
                  (byte) op.getPadding(),
                  (byte) op.getBlockMode(),
                  KMByteBlob.getBuffer(data[SECRET]),
                  KMByteBlob.getStartOff(data[SECRET]),
                  KMByteBlob.length(data[SECRET]),
                  KMByteBlob.getBuffer(data[IV]),
                  KMByteBlob.getStartOff(data[IV]),
                  KMByteBlob.length(data[IV]),
                  op.getMacLength()));
        } catch (CryptoException exception) {
          if (exception.getReason() == CryptoException.ILLEGAL_VALUE) {
            KMException.throwIt(KMError.INVALID_ARGUMENT);
          } else if (exception.getReason() == CryptoException.NO_SUCH_ALGORITHM) {
            KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
          }
        }
    }
  }

  private void beginTrustedConfirmationOperation(KMOperationState op) {
    // Check for trusted confirmation - if required then set the signer in op state.
    if (KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.BOOL_TAG,
        KMType.TRUSTED_CONFIRMATION_REQUIRED) != KMType.INVALID_VALUE) {

      op.setTrustedConfirmationSigner(
          seProvider.initTrustedConfirmationSymmetricOperation(storeDataInst.getComputedHmacKey()));

      op.getTrustedConfirmationSigner().update(
          confirmationToken,
          (short) 0,
          (short) confirmationToken.length);
    }

  }

  private void beginSignVerifyOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.SIGN) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte) op.getAlgorithm(),
                    (byte) op.getPadding(),
                    (byte) op.getDigest(),
                    KMType.DIGEST_NONE, /* No MGF Digest */
                    KMByteBlob.getBuffer(data[SECRET]),
                    KMByteBlob.getStartOff(data[SECRET]),
                    KMByteBlob.length(data[SECRET]),
                    KMByteBlob.getBuffer(data[PUB_KEY]),
                    KMByteBlob.getStartOff(data[PUB_KEY]),
                    KMByteBlob.length(data[PUB_KEY])));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.EC:
        try {
          if (op.getPurpose() == KMType.SIGN) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    (byte) op.getAlgorithm(),
                    (byte) op.getPadding(),
                    (byte) op.getDigest(),
                    KMType.DIGEST_NONE, /* No MGF Digest */
                    KMByteBlob.getBuffer(data[SECRET]),
                    KMByteBlob.getStartOff(data[SECRET]),
                    KMByteBlob.length(data[SECRET]),
                    null,
                    (short) 0,
                    (short) 0));
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException exp) {
          // Javacard does not support NO digest based signing.
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      case KMType.HMAC:
        // As per Keymaster HAL documentation, the length of the Hmac output can
        // be decided by using TAG_MAC_LENGTH in Keyparameters. But there is no
        // such provision to control the length of the Hmac output using JavaCard
        // crypto APIs and the current implementation always returns 32 bytes
        // length of Hmac output. So to provide support to TAG_MAC_LENGTH
        // feature, we truncate the output signature to TAG_MAC_LENGTH and return
        // the truncated signature back to the caller. At the time of verfication
        // we again compute the signature of the plain text input, truncate it to
        // TAG_MAC_LENGTH and compare it with the input signature for
        // verification. So this is the reason we are using KMType.SIGN directly
        // instead of using op.getPurpose().
        try {
          op.setOperation(
              seProvider.initSymmetricOperation(
                  (byte) KMType.SIGN,
                  (byte) op.getAlgorithm(),
                  (byte) op.getDigest(),
                  (byte) op.getPadding(),
                  (byte) op.getBlockMode(),
                  KMByteBlob.getBuffer(data[SECRET]),
                  KMByteBlob.getStartOff(data[SECRET]),
                  KMByteBlob.length(data[SECRET]),
                  null,
                  (short) 0,
                  (short) 0,
                  (short) 0));
        } catch (CryptoException exp) {
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        }
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
  }

  private boolean isHwAuthTokenContainsMatchingSecureId(short hwAuthToken,
      short secureUserIdsObj) {
    short secureUserId = KMHardwareAuthToken.getUserId(hwAuthToken);
    if (!KMInteger.isZero(secureUserId)) {
      if (KMIntegerArrayTag.contains(secureUserIdsObj, secureUserId)) {
        return true;
      }
    }

    short authenticatorId = KMHardwareAuthToken.getAuthenticatorId(hwAuthToken);
    if (!KMInteger.isZero(authenticatorId)) {
      if (KMIntegerArrayTag.contains(secureUserIdsObj, authenticatorId)) {
        return true;
      }
    }
    return false;
  }

  private boolean authTokenMatches(short userSecureIdsPtr, short authType,
      byte[] scratchPad) {
    if (!validateHwToken(data[HW_TOKEN], scratchPad)) {
      return false;
    }
    if (!isHwAuthTokenContainsMatchingSecureId(data[HW_TOKEN], userSecureIdsPtr)) {
      return false;
    }
    // check auth type
    tmpVariables[2] = KMHardwareAuthToken.getHwAuthenticatorType(data[HW_TOKEN]);
    tmpVariables[2] = KMEnum.getVal(tmpVariables[2]);
    if (((byte) tmpVariables[2] & (byte) authType) == 0) {
      return false;
    }
    return true;
  }

  private void authorizeUserSecureIdAuthTimeout(KMOperationState op, byte[] scratchPad) {
    short authTime;
    short authType;
    // Authorize User Secure Id and Auth timeout
    short userSecureIdPtr =
        KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID);
    if (userSecureIdPtr != KMType.INVALID_VALUE) {
      // Authentication required.
      if (KMType.INVALID_VALUE !=
          KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED)) {
        // Key has both USER_SECURE_ID and NO_AUTH_REQUIRED
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      // authenticator type must be provided.
      if (KMType.INVALID_VALUE ==
          (authType = KMEnumTag.getValue(KMType.USER_AUTH_TYPE, data[HW_PARAMETERS]))) {
        // Authentication required, but no auth type found.
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }

      short authTimeoutTagPtr =
          KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.UINT_TAG, KMType.AUTH_TIMEOUT);
      if (authTimeoutTagPtr != KMType.INVALID_VALUE) {
        // authenticate user
        if (!authTokenMatches(userSecureIdPtr, authType, scratchPad)) {
          KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
        }

        authTimeoutTagPtr =
            KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.ULONG_TAG,
                KMType.AUTH_TIMEOUT_MILLIS);
        if (authTimeoutTagPtr == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_KEY_BLOB);
        }
        authTime = KMIntegerTag.getValue(authTimeoutTagPtr);
        // set the one time auth
        op.setOneTimeAuthReqd(true);
        // set the authentication time stamp in operation state
        authTime =
            addIntegers(authTime,
                KMHardwareAuthToken.getTimestamp(data[HW_TOKEN]), scratchPad);
        op.setAuthTime(
            KMInteger.getBuffer(authTime), KMInteger.getStartOff(authTime));
        // auth time validation will happen in update or finish
        op.setAuthTimeoutValidated(false);
      } else {
        // auth per operation required
        // store user secure id and authType in OperationState.
        op.setUserSecureId(userSecureIdPtr);
        op.setAuthType((byte) authType);
        // set flags
        op.setOneTimeAuthReqd(false);
        op.setAuthPerOperationReqd(true);
      }
    }
  }

  private boolean verifyHwTokenMacInBigEndian(short hwToken, byte[] scratchPad) {
    // The challenge, userId and authenticatorId, authenticatorType and timestamp
    // are in network order (big-endian).
    short len = 0;
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.getChallenge(hwToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.getUserId(hwToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.getAuthenticatorId(hwToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.getHwAuthenticatorType(hwToken);
    scratchPad[(short) (len + 3)] = KMEnum.getVal(ptr);
    len += 4;
    // concatenate timestamp -8 bytes
    ptr = KMHardwareAuthToken.getTimestamp(hwToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;

    ptr = KMHardwareAuthToken.getMac(hwToken);

    return seProvider.hmacVerify(
        storeDataInst.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.getBuffer(ptr),
        KMByteBlob.getStartOff(ptr),
        KMByteBlob.length(ptr));
  }

  private boolean verifyHwTokenMacInLittleEndian(short hwToken, byte[] scratchPad) {
    // The challenge, userId and authenticatorId values are in little endian order,
    // but authenticatorType and timestamp are in network order (big-endian).
    short len = 0;
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.getChallenge(hwToken);
    KMInteger.toLittleEndian(ptr, scratchPad, len);
    len += 8;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.getUserId(hwToken);
    KMInteger.toLittleEndian(ptr, scratchPad, len);
    len += 8;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.getAuthenticatorId(hwToken);
    KMInteger.toLittleEndian(ptr, scratchPad, len);
    len += 8;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.getHwAuthenticatorType(hwToken);
    scratchPad[(short) (len + 3)] = KMEnum.getVal(ptr);
    len += 4;
    // concatenate timestamp - 8 bytes
    ptr = KMHardwareAuthToken.getTimestamp(hwToken);
    KMInteger.value(ptr, scratchPad, (short) (len + (short) (8 - KMInteger.length(ptr))));
    len += 8;

    ptr = KMHardwareAuthToken.getMac(hwToken);

    return seProvider.hmacVerify(
        storeDataInst.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.getBuffer(ptr),
        KMByteBlob.getStartOff(ptr),
        KMByteBlob.length(ptr));
  }

  private boolean validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.getMac(hwToken);
    // If mac length is zero then token is empty.
    if (KMByteBlob.length(ptr) == 0) {
      return false;
    }
    if (KMConfigurations.TEE_MACHINE_TYPE == KMConfigurations.LITTLE_ENDIAN) {
      return verifyHwTokenMacInLittleEndian(hwToken, scratchPad);
    } else {
      return verifyHwTokenMacInBigEndian(hwToken, scratchPad);
    }
  }

  private short importKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 3);
    // Arguments
    short params = KMKeyParameters.expAny();
    KMArray.add(cmd, (short) 0, params);
    KMArray.add(cmd, (short) 1, KMEnum.instance(KMType.KEY_FORMAT));
    KMArray.add(cmd, (short) 2, KMByteBlob.exp());
    return receiveIncoming(apdu, cmd);
  }

  private void processImportKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = importKeyCmd(apdu);
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 0);
    short keyFmt = KMArray.get(cmd, (short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.get(cmd, (short) 2);
    keyFmt = KMEnum.getVal(keyFmt);

    data[CERTIFICATE] = KMArray.instance((short) 0); //by default the cert is empty.
    data[ORIGIN] = KMType.IMPORTED;
    importKey(apdu, keyFmt, scratchPad);
  }

  private short importWrappedKeyCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 12);
    // Arguments
    short params = KMKeyParameters.exp();
    short bBlob = KMByteBlob.exp();
    KMArray.add(cmd, (short) 0, params); // Key Params of wrapped key
    KMArray.add(cmd, (short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.add(cmd, (short) 2, bBlob); // Wrapped Import Key Blob
    KMArray.add(cmd, (short) 3, bBlob); // Auth Tag
    KMArray.add(cmd, (short) 4, bBlob); // IV - Nonce
    KMArray.add(cmd, (short) 5, bBlob); // Encrypted Transport Key
    KMArray.add(cmd, (short) 6, bBlob); // Wrapping Key KeyBlob
    KMArray.add(cmd, (short) 7, bBlob); // Masking Key
    KMArray.add(cmd, (short) 8, params); // Un-wrapping Params
    KMArray.add(cmd, (short) 9, bBlob); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.add(cmd, (short) 10, KMInteger.exp()); // Password Sid
    KMArray.add(cmd, (short) 11, KMInteger.exp()); // Biometric Sid
    return receiveIncoming(apdu, cmd);
  }

  private void processImportWrappedKeyCmd(APDU apdu) {

    byte[] scratchPad = apdu.getBuffer();
    short cmd = importWrappedKeyCmd(apdu);

    // Step -0 - check whether the key format and algorithm supported
    // read algorithm
    tmpVariables[0] = KMArray.get(cmd, (short) 0);
    tmpVariables[1] = KMEnumTag.getValue(KMType.ALGORITHM, tmpVariables[0]);
    // read key format
    tmpVariables[2] = KMArray.get(cmd, (short) 1);
    byte keyFormat = KMEnum.getVal(tmpVariables[2]);
    if ((tmpVariables[1] == KMType.RSA || tmpVariables[1] == KMType.EC)
        && (keyFormat != KMType.PKCS8)) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }

    // Step -1 parse the wrapping key blob
    // read wrapping key blob
    data[KEY_BLOB] = KMArray.get(cmd, (short) 6);
    // read un wrapping key params
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 8);
    // Read App Id and App Data if any from un wrapping key params
    data[APP_ID] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_ID);
    data[APP_DATA] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_DATA);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.getValue(data[APP_ID]);
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.getValue(data[APP_DATA]);
    }
    // parse the wrapping key blob
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    // check whether the wrapping key is RSA with purpose KEY_WRAP, padding RSA_OAEP and Digest
    // SHA2_256.
    if (KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]) != KMType.RSA) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
    }
    if (!KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
    }
    if (!KMEnumArrayTag.contains(KMType.PADDING, KMType.RSA_OAEP, data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.INCOMPATIBLE_PADDING_MODE);
    }
    if (!KMEnumArrayTag.contains(KMType.PURPOSE, KMType.WRAP_KEY, data[HW_PARAMETERS])) {
      KMException.throwIt((KMError.INCOMPATIBLE_PURPOSE));
    }

    // Step 2 - decrypt the encrypted transport key - 32 bytes AES-GCM key
    // create rsa decipher
    // read encrypted transport key from args
    tmpVariables[0] = KMArray.get(cmd, (short) 5);
    // Decrypt the transport key
    tmpVariables[1] =
        seProvider.rsaDecipherOAEP256(
            KMByteBlob.getBuffer(data[SECRET]),
            KMByteBlob.getStartOff(data[SECRET]),
            KMByteBlob.length(data[SECRET]),
            KMByteBlob.getBuffer(data[PUB_KEY]),
            KMByteBlob.getStartOff(data[PUB_KEY]),
            KMByteBlob.length(data[PUB_KEY]),
            KMByteBlob.getBuffer(tmpVariables[0]),
            KMByteBlob.getStartOff(tmpVariables[0]),
            KMByteBlob.length(tmpVariables[0]),
            scratchPad,
            (short) 0);
    data[PUB_KEY] = KMType.INVALID_VALUE;
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[1]);

    // Step 3 - XOR the decrypted AES-GCM key with with masking key
    // read masking key
    tmpVariables[0] = KMArray.get(cmd, (short) 7);
    tmpVariables[1] = KMByteBlob.length(tmpVariables[0]);
    // Length of masking key and transport key must be same.
    if (tmpVariables[1] != KMByteBlob.length(data[SECRET])) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    tmpVariables[2] = 0; // index
    // Xor every byte of masking and key and store the result in data[SECRET]
    while (tmpVariables[2] < tmpVariables[1]) {
      tmpVariables[3] =
          (short) (((short) KMByteBlob.get(tmpVariables[0], tmpVariables[2])) & 0x00FF);
      tmpVariables[4] =
          (short) (((short) KMByteBlob.get(data[SECRET], tmpVariables[2])) & 0x00FF);
      KMByteBlob.add(data[SECRET], tmpVariables[2], (byte) (tmpVariables[3] ^ tmpVariables[4]));
      tmpVariables[2]++;
    }

    // Step 4 - AES-GCM decrypt the wrapped key
    data[INPUT_DATA] = KMArray.get(cmd, (short) 2);
    data[AUTH_DATA] = KMArray.get(cmd, (short) 9);
    data[AUTH_TAG] = KMArray.get(cmd, (short) 3);
    data[NONCE] = KMArray.get(cmd, (short) 4);
    Util.arrayFillNonAtomic(
        scratchPad, (short) 0, KMByteBlob.length(data[INPUT_DATA]), (byte) 0);

    if (!seProvider.aesGCMDecrypt(
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        KMByteBlob.getBuffer(data[INPUT_DATA]),
        KMByteBlob.getStartOff(data[INPUT_DATA]),
        KMByteBlob.length(data[INPUT_DATA]),
        scratchPad,
        (short) 0,
        KMByteBlob.getBuffer(data[NONCE]),
        KMByteBlob.getStartOff(data[NONCE]),
        KMByteBlob.length(data[NONCE]),
        KMByteBlob.getBuffer(data[AUTH_DATA]),
        KMByteBlob.getStartOff(data[AUTH_DATA]),
        KMByteBlob.length(data[AUTH_DATA]),
        KMByteBlob.getBuffer(data[AUTH_TAG]),
        KMByteBlob.getStartOff(data[AUTH_TAG]),
        KMByteBlob.length(data[AUTH_TAG]))) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }

    // Step 5 - Import decrypted key
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 0);
    // create key blob array
    data[IMPORTED_KEY_BLOB] = KMByteBlob.instance(scratchPad, (short) 0,
        KMByteBlob.length(data[INPUT_DATA]));
    importKey(apdu, keyFormat, scratchPad);
  }

  private void validateImportKey(short params, short keyFmt) {
    validatePurpose(params);
    // Rollback protection not supported
    KMTag.assertAbsence(params, KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
        KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    validateEarlyBoot(params, INS_IMPORT_KEY_CMD, null, (short) 0, KMError.EARLY_BOOT_ENDED);
    //Check if the tags are supported.
    if (KMKeyParameters.hasUnsupportedTags(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_TAG);
    }
    // Algorithm must be present
    KMTag.assertPresence(params, KMType.ENUM_TAG, KMType.ALGORITHM, KMError.INVALID_ARGUMENT);
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, params);
    // key format must be raw if aes, des or hmac and pkcs8 for rsa and ec.
    if ((alg == KMType.AES || alg == KMType.DES || alg == KMType.HMAC) && keyFmt != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    if ((alg == KMType.RSA || alg == KMType.EC) && keyFmt != KMType.PKCS8) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
  }

  public void validatePurpose(short params) {
    return;
  }

  private void importKey(APDU apdu, short keyFmt, byte[] scratchPad) {
    validateImportKey(data[KEY_PARAMETERS], keyFmt);
    // Check algorithm and dispatch to appropriate handler.
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    switch (alg) {
      case KMType.RSA:
        importRSAKey(scratchPad);
        break;
      case KMType.AES:
        importAESKey(scratchPad);
        break;
      case KMType.DES:
        importTDESKey(scratchPad);
        break;
      case KMType.HMAC:
        importHmacKey(scratchPad);
        break;
      case KMType.EC:
        importECKeys(scratchPad);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
    makeKeyCharacteristics(scratchPad);
    createEncryptedKeyBlob(scratchPad);
    // prepare the response
    short resp = KMArray.instance((short) 3);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, data[KEY_BLOB]);
    KMArray.add(resp, (short) 2, data[KEY_CHARACTERISTICS]);
    sendOutgoing(apdu, resp);
  }

  public short decodeRawECKey(short rawBlob) {
    // Decode key material
    short arrPtr = KMArray.instance((short) 2);
    KMArray.add(arrPtr, (short) 0, KMByteBlob.exp()); // secret
    KMArray.add(arrPtr, (short) 1, KMByteBlob.exp()); // public key
    arrPtr =
        decoder.decode(
            arrPtr,
            KMByteBlob.getBuffer(rawBlob),
            KMByteBlob.getStartOff(rawBlob),
            KMByteBlob.length(rawBlob));
    return arrPtr;
  }

  private void importECKeys(byte[] scratchPad) {
    // Decode key material
    KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
    short keyBlob = pkcs8.decodeEc(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.get(keyBlob, (short) 0);
    data[SECRET] = KMArray.get(keyBlob, (short) 1);
    // initialize 256 bit p256 key for given private key and public key.
    short index = 0;
    // check whether the key size tag is present in key parameters.
    short keySize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    short SecretLen = (short) (KMByteBlob.length(data[SECRET]) * 8);
    if (keySize != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret for 256 curve should be between
      // 256-383
      if (((256 <= SecretLen) && (383 >= SecretLen)) ^ keySize == 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (keySize != 256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    } else {
      if ((256 > SecretLen) || (383 < SecretLen)) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      // add the key size to scratchPad
      keySize = KMInteger.uint_16((short) 256);
      keySize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keySize);
      Util.setShort(scratchPad, index, keySize);
      index += 2;
    }
    // check the curve if present in key parameters.
    short curve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (curve != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret length for 256 curve should be between
      // 256-383
      if (((256 <= SecretLen) && (383 >= SecretLen)) ^ curve == KMType.P_256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (curve != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
      }
    } else {
      if ((256 > SecretLen) || (383 < SecretLen)) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      // add the curve to scratchPad
      curve = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
      Util.setShort(scratchPad, index, curve);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.EC,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        KMByteBlob.getBuffer(data[PUB_KEY]),
        KMByteBlob.getStartOff(data[PUB_KEY]),
        KMByteBlob.length(data[PUB_KEY]));

    // add scratch pad to key parameters
    updateKeyParameters(scratchPad, index);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void importHmacKey(byte[] scratchPad) {
    // Get Key
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    // create HMAC key of up to 512 bit
    short index = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (!(keysize >= 64 && keysize <= 512 && keysize % 8 == 0)) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      if (keysize != (short) (KMByteBlob.length(data[SECRET]) * 8)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      keysize = (short) (KMByteBlob.length(data[SECRET]) * 8);
      if (!(keysize >= 64 && keysize <= 512 && keysize % 8 == 0)) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      keysize = KMInteger.uint_16(keysize);
      short keySizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keySizeTag);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.HMAC,
        keysize,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]));

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate HMAC Key parameters
    validateHmacKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importTDESKey(byte[] scratchPad) {
    // Decode Key Material
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    short index = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != 168) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      if (192 != (short) (8 * KMByteBlob.length(data[SECRET]))) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      keysize = (short) (KMByteBlob.length(data[SECRET]) * 8);
      if (keysize != 192) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      // add the key size to scratchPad
      keysize = KMInteger.uint_16((short) 168);
      short keysizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysizeTag);
      index += 2;
    }
    // Read Minimum Mac length - it must not be present
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
        KMError.INVALID_TAG);
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.DES,
        keysize,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]));
    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void validateAesKeySize(short keySizeBits) {
    if (keySizeBits != 128 && keySizeBits != 256) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private void importAESKey(byte[] scratchPad) {
    // Get Key
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    // create 128 or 256 bit AES key
    short index = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != (short) (8 * KMByteBlob.length(data[SECRET]))) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      validateAesKeySize(keysize);
    } else {
      // add the key size to scratchPad
      keysize = (short) (8 * KMByteBlob.length(data[SECRET]));
      validateAesKeySize(keysize);
      keysize = KMInteger.uint_16(keysize);
      short keysizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysizeTag);
      index += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.AES,
        keysize,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]));

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate AES Key parameters
    validateAESKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importRSAKey(byte[] scratchPad) {
    // Decode key material
    KMPKCS8Decoder pkcs8 = KMPKCS8Decoder.instance();
    short keyblob = pkcs8.decodeRsa(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.get(keyblob, (short) 0);
    short pubKeyExp = KMArray.get(keyblob, (short) 1);
    data[SECRET] = KMArray.get(keyblob, (short) 2);
    if (F4.length != KMByteBlob.length(pubKeyExp)) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    if (Util.arrayCompare(F4, (short) 0, KMByteBlob.getBuffer(pubKeyExp),
        KMByteBlob.getStartOff(pubKeyExp), (short) F4.length) != 0) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    short index = 0; // index in scratchPad for update parameters.
    // validate public exponent if present in key params - it must be 0x010001
    short len =
        KMIntegerTag.getValue(
            scratchPad,
            (short) 10, // using offset 10 as first 10 bytes reserved for update params
            KMType.ULONG_TAG,
            KMType.RSA_PUBLIC_EXPONENT,
            data[KEY_PARAMETERS]);
    if (len != KMTag.INVALID_VALUE) {
      if (len != 4
          || Util.getShort(scratchPad, (short) 10) != 0x01
          || Util.getShort(scratchPad, (short) 12) != 0x01) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add public exponent to scratchPad
      Util.setShort(scratchPad, (short) 10, (short) 0x01);
      Util.setShort(scratchPad, (short) 12, (short) 0x01);
      pubKeyExp = KMInteger.uint_32(scratchPad, (short) 10);
      pubKeyExp =
          KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, pubKeyExp);
      Util.setShort(scratchPad, index, pubKeyExp);
      index += 2;
    }

    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    short kSize = (short) (KMByteBlob.length(data[SECRET]) * 8);
    if (keysize != KMType.INVALID_VALUE) {
      if (keysize != 2048
          || keysize != kSize) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      if (2048 != kSize) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      // add the key size to scratchPad
      keysize = KMInteger.uint_16((short) 2048);
      keysize = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, index, keysize);
      index += 2;
    }

    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.RSA,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        KMByteBlob.getBuffer(data[PUB_KEY]),
        KMByteBlob.getStartOff(data[PUB_KEY]),
        KMByteBlob.length(data[PUB_KEY]));

    // update the key parameters list
    updateKeyParameters(scratchPad, index);
    // validate RSA Key parameters
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void updateKeyParameters(byte[] newParams, short len) {
    if (len == 0) {
      return; // nothing to update
    }
    // Create Update Param array and copy current params
    short params = KMKeyParameters.getVals(data[KEY_PARAMETERS]);
    len = (short) (KMArray.length(params) + (short) (len / 2));
    short updatedParams = KMArray.instance(len); // update params

    len = KMArray.length(params);
    short index = 0;

    // copy the existing key parameters to updated array
    while (index < len) {
      short tag = KMArray.get(params, index);
      KMArray.add(updatedParams, index, tag);
      index++;
    }

    // copy new parameters to updated array
    len = KMArray.length(updatedParams);
    short newParamIndex = 0; // index in ptrArr
    while (index < len) {
      short tag = Util.getShort(newParams, newParamIndex);
      KMArray.add(updatedParams, index, tag);
      index++;
      newParamIndex += 2;
    }
    // replace with updated key parameters.
    data[KEY_PARAMETERS] = KMKeyParameters.instance(updatedParams);
  }

  private short initStrongBoxCmd(APDU apdu) {
    short cmd = KMArray.instance((short) 3);
    KMArray.add(cmd, (short) 0, KMInteger.exp()); //OS version
    KMArray.add(cmd, (short) 1, KMInteger.exp()); //OS patch level
    KMArray.add(cmd, (short) 2, KMInteger.exp()); //Vendor patch level
    return receiveIncoming(apdu, cmd);
  }

  // This command is executed to set the boot parameters.
  // releaseAllOperations has to be called on every boot, so
  // it is called from inside initStrongBoxCmd. Later in future if
  // initStrongBoxCmd is removed, then make sure that releaseAllOperations
  // is moved to a place where it is called on every boot.
  private void processInitStrongBoxCmd(APDU apdu) {
    short cmd = initStrongBoxCmd(apdu);

    short osVersion = KMArray.get(cmd, (short) 0);
    short osPatchLevel = KMArray.get(cmd, (short) 1);
    short vendorPatchLevel = KMArray.get(cmd, (short) 2);
    setOsVersion(osVersion);
    setOsPatchLevel(osPatchLevel);
    setVendorPatchLevel(vendorPatchLevel);
  }

  public void reboot(byte[] scratchPad, short offset) {
    storeDataInst.clearData(KMDataStoreConstants.HMAC_NONCE);
    //flag to maintain the boot state
    storeDataInst.clearData(KMDataStoreConstants.BOOT_ENDED_STATUS);
    //flag to maintain early boot ended state
    storeDataInst.clearData(KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS);
    //Clear all the operation state.
    releaseAllOperations();
    // Hmac is cleared, so generate a new Hmac nonce.
    initHmacNonceAndSeed(scratchPad, offset);
    // Clear all auth tags.
    storeDataInst.clearAllAuthTags();
  }

  protected void initSystemBootParams() {
    short empty = KMInteger.uint_16((short) 0);
    setOsVersion(empty);
    setOsPatchLevel(empty);
    setVendorPatchLevel(empty);
  }

  protected void setOsVersion(short version) {
    writeData(KMDataStoreConstants.OS_VERSION, KMInteger.getBuffer(version),
        KMInteger.getStartOff(version),
        KMInteger.length(version));
  }

  protected void setOsPatchLevel(short patch) {
    writeData(KMDataStoreConstants.OS_PATCH_LEVEL, KMInteger.getBuffer(patch),
        KMInteger.getStartOff(patch),
        KMInteger.length(patch));
  }

  protected void setVendorPatchLevel(short patch) {
    writeData(KMDataStoreConstants.VENDOR_PATCH_LEVEL, KMInteger.getBuffer(patch),
        KMInteger.getStartOff(patch),
        KMInteger.length(patch));
  }

  private short generateKeyCmd(APDU apdu) {
    short params = KMKeyParameters.expAny();
    // Array of expected arguments
    short cmd = KMArray.instance((short) 1);
    KMArray.add(cmd, (short) 0, params); //key params
    return receiveIncoming(apdu, cmd);
  }

  private void processGenerateKey(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = generateKeyCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    data[KEY_PARAMETERS] = KMArray.get(cmd, (short) 0);
    data[CERTIFICATE] = KMArray.instance((short) 0); //by default the cert is empty.
    // ROLLBACK_RESISTANCE not supported.
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE,
        KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    // BOOTLOADER_ONLY keys not supported.
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY,
        KMError.INVALID_KEY_BLOB);
    // Algorithm must be present
    KMTag.assertPresence(data[KEY_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM,
        KMError.INVALID_ARGUMENT);
    // As per specification Early boot keys may be created after early boot ended.
    validateEarlyBoot(data[KEY_PARAMETERS], INS_GENERATE_KEY_CMD, scratchPad, (short) 0,
        KMError.EARLY_BOOT_ENDED);
    validatePurpose(data[KEY_PARAMETERS]);
    //Check if the tags are supported.
    if (KMKeyParameters.hasUnsupportedTags(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_TAG);
    }
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    // Check algorithm and dispatch to appropriate handler.
    switch (alg) {
      case KMType.RSA:
        generateRSAKey(scratchPad);
        break;
      case KMType.AES:
        generateAESKey(scratchPad);
        break;
      case KMType.DES:
        generateTDESKey(scratchPad);
        break;
      case KMType.HMAC:
        generateHmacKey(scratchPad);
        break;
      case KMType.EC:
        generateECKeys(scratchPad);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }

    // create key blob and associated attestation.
    data[ORIGIN] = KMType.GENERATED;
    makeKeyCharacteristics(scratchPad);
    createEncryptedKeyBlob(scratchPad);
    // prepare the response
    short resp = KMArray.instance((short) 3);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, data[KEY_BLOB]);
    KMArray.add(resp, (short) 2, data[KEY_CHARACTERISTICS]);
    sendOutgoing(apdu, resp);
  }

  public void processAttestationCertDataCmd(APDU apdu) {
    // TODO optimize this function.
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
    // Buffer holds the corresponding offsets and lengths of the certChain, certIssuer and certExpiry
    // in the bufferRef[0] buffer.
    short var = KMByteBlob.instance((short) 12);
    // These variables point to the appropriate positions in the var buffer.
    short certChainPos = KMByteBlob.getStartOff(var);
    short certIssuerPos = (short) (KMByteBlob.getStartOff(var) + 4);
    short certExpiryPos = (short) (KMByteBlob.getStartOff(var) + 8);
    decoder.decodeCertificateData((short) 3,
        buffer, bufferStartOffset, bufferLength,
        KMByteBlob.getBuffer(var), KMByteBlob.getStartOff(var));
    // persist data
    storeDataInst.persistCertificateData(
        (byte[]) buffer,
        Util.getShort(KMByteBlob.getBuffer(var), certChainPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certChainPos + 2)), // length
        Util.getShort(KMByteBlob.getBuffer(var), certIssuerPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certIssuerPos + 2)), // length
        Util.getShort(KMByteBlob.getBuffer(var), certExpiryPos), // offset
        Util.getShort(KMByteBlob.getBuffer(var), (short) (certExpiryPos + 2))); // length

    // reclaim memory
    repository.reclaimMemory(bufferLength);
  }

  private short generateAttestKeyCmd(APDU apdu) {
    return receiveIncoming(apdu, generateAttestKeyExp());
  }

  protected void processGetCertChainCmd(APDU apdu) {
    // Make the response
    short certChainLen = storeDataInst.getCertificateDataLength(
        KMDataStoreConstants.CERTIFICATE_CHAIN);
    short int32Ptr = KMInteger.uint_16(KMError.OK);
    short maxByteHeaderLen = 3; // Maximum possible ByteBlob header len.
    short arrayHeaderLen = 1;
    // Allocate maximum possible buffer.
    // Add arrayHeader + (PowerResetStatus + KMError.OK) + Byte Header
    encoder.getEncodedLength(int32Ptr);
    short totalLen = (short) (arrayHeaderLen + encoder.getEncodedLength(int32Ptr) + maxByteHeaderLen
        + certChainLen);
    short certChain = KMByteBlob.instance(totalLen);
    // copy the certificate chain to the end of the buffer.
    storeDataInst.readCertificateData(
        KMDataStoreConstants.CERTIFICATE_CHAIN,
        KMByteBlob.getBuffer(certChain),
        (short) (KMByteBlob.getStartOff(certChain) + totalLen - certChainLen));
    // Encode cert chain.
    encoder.encodeCertChain(
        KMByteBlob.getBuffer(certChain),
        KMByteBlob.getStartOff(certChain),
        KMByteBlob.length(certChain),
        int32Ptr, // uint32 ptr
        (short) (KMByteBlob.getStartOff(certChain) + totalLen - certChainLen),
        // start pos of cert chain.
        certChainLen);
    apdu.setOutgoing();
    apdu.setOutgoingLength(KMByteBlob.length(certChain));
    apdu.sendBytesLong(KMByteBlob.getBuffer(certChain),
        KMByteBlob.getStartOff(certChain),
        KMByteBlob.length(certChain));
  }

  private void processAttestKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    short cmd = generateAttestKeyCmd(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    getAttestKeyInputParameters(cmd, data, KEY_BLOB, KEY_PARAMETERS, ATTEST_KEY_BLOB,
        ATTEST_KEY_PARAMS, ATTEST_KEY_ISSUER);
    data[CERTIFICATE] = KMArray.instance((short) 0); //by default the cert is empty.

    // Check for app id and app data.
    data[APP_ID] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_ID);
    data[APP_DATA] =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG, KMType.APPLICATION_DATA);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.getValue(data[APP_ID]);
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.getValue(data[APP_DATA]);
    }
    // parse key blob
    parseEncryptedKeyBlob(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad);
    // The key which is being attested should be asymmetric i.e. RSA or EC
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if (alg != KMType.RSA && alg != KMType.EC) {
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    // Build certificate
    generateAttestation(data[ATTEST_KEY_BLOB], data[ATTEST_KEY_PARAMS], scratchPad);

    short resp = KMArray.instance((short) 2);
    KMArray.add(resp, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(resp, (short) 1, data[CERTIFICATE]);
    sendOutgoing(apdu, resp);
  }

  private short getAttestationMode(short attKeyBlob, short attChallenge) {
    short alg = KMKeyParameters.findTag(data[HW_PARAMETERS], KMType.ENUM_TAG, KMType.ALGORITHM);
    short mode = KMType.NO_CERT;
    // TODO Keymaster specification: Symmetric keys with challenge should return error.
    if (KMEnumTag.getValue(alg) != KMType.RSA &&
        KMEnumTag.getValue(alg) != KMType.EC) {
      return mode;
    }
    // If attestation keyblob present
    if (attKeyBlob != KMType.INVALID_VALUE && KMByteBlob.length(attKeyBlob) > 0) {
      // No attestation challenge present then it is an error
      if (attChallenge == KMType.INVALID_VALUE || KMByteBlob.length(attChallenge) <= 0) {
        KMException.throwIt(KMError.ATTESTATION_CHALLENGE_MISSING);
      } else {
        mode = KMType.ATTESTATION_CERT;
      }
    } else {
      mode = getSupportedAttestationMode(attChallenge);
    }
    return mode;
  }

  private void generateAttestation(short attKeyBlob, short attKeyParam, byte[] scratchPad) {
    // Device unique attestation not supported
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.BOOL_TAG, KMType.DEVICE_UNIQUE_ATTESTATION,
        KMError.CANNOT_ATTEST_IDS);
    // Read attestation challenge if present
    short attChallenge =
        KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.BYTES_TAG,
            KMType.ATTESTATION_CHALLENGE);
    if (attChallenge != KMType.INVALID_VALUE) {
      attChallenge = KMByteTag.getValue(attChallenge);
    }
    // No attestation required for symmetric keys
    short mode = getAttestationMode(attKeyBlob, attChallenge);
    KMAttestationCert cert = null;

    switch (mode) {
      case KMType.ATTESTATION_CERT:
        cert = makeAttestationCert(attKeyBlob, attKeyParam, attChallenge, data[ATTEST_KEY_ISSUER],
            data[HW_PARAMETERS], data[SW_PARAMETERS], data[KEY_PARAMETERS], scratchPad);
        break;
      case KMType.SELF_SIGNED_CERT:
        //cert = makeCert(attKeyBlob, attKeyParam, scratchPad);
        cert = makeSelfSignedCert(data[SECRET], data[PUB_KEY], scratchPad);
        break;
      case KMType.FACTORY_PROVISIONED_ATTEST_CERT:
        cert = makeCertWithFactoryProvisionedKey(attChallenge, scratchPad);
        break;
      case KMType.FAKE_CERT:
        //cert = makeCert(attKeyBlob, attKeyParam, scratchPad);
        cert = makeSelfSignedCert(KMType.INVALID_VALUE, data[PUB_KEY], scratchPad);
        break;
      default:
        data[CERTIFICATE] = KMArray.instance((short) 0);
        return;
    }
    // Allocate memory
    short certData = KMByteBlob.instance(MAX_CERT_SIZE);

    cert.buffer(KMByteBlob.getBuffer(certData),
        KMByteBlob.getStartOff(certData),
        KMByteBlob.length(certData));

    // Build the certificate - this will sign the cert
    cert.build();
    // Adjust the start and length of the certificate in the blob
    KMByteBlob.setStartOff(certData, cert.getCertStart());
    KMByteBlob.setLength(certData, cert.getCertLength());
    // Initialize the certificate as array of blob
    data[CERTIFICATE] = KMArray.instance((short) 1);
    KMArray.add(data[CERTIFICATE], (short) 0, certData);
  }

  /**
   * 1) If attestation key is present and attestation challenge is absent then it is an error. 2) If
   * attestation key is absent and attestation challenge is present then it is an error as factory
   * provisioned attestation key is not supported. 3) If both are present and issuer is absent or
   * attest key purpose is not ATTEST_KEY then it is an error. 4) If the generated/imported keys are
   * RSA or EC then validity period must be specified. Device Unique Attestation is not supported.
   */

  private static void validateRSAKey(byte[] scratchPad) {
    // Read key size
    if (!KMTag.isValidKeySize(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    if (!KMTag.isValidPublicExponent(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  // Generate key handlers
  private void generateRSAKey(byte[] scratchPad) {
    // Validate RSA Key
    validateRSAKey(scratchPad);
    // Now generate 2048 bit RSA keypair for the given exponent
    short[] lengths = tmpVariables;
    data[PUB_KEY] = KMByteBlob.instance((short) 256);
    data[SECRET] = KMByteBlob.instance((short) 256);
    seProvider.createAsymmetricKey(
        KMType.RSA,
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        KMByteBlob.getBuffer(data[PUB_KEY]),
        KMByteBlob.getStartOff(data[PUB_KEY]),
        KMByteBlob.length(data[PUB_KEY]),
        lengths);

    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateAESKey() {
    // Read key size
    if (!KMTag.isValidKeySize(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Block mode - array of byte values
    if (KMTag.isPresent(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE)) {
      short blockModes =
          KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE);
      // If it is a GCM mode
      if (KMEnumArrayTag.contains(blockModes, KMType.GCM)) {
        // Min mac length must be present
        KMTag.assertPresence(data[KEY_PARAMETERS], KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
            KMError.MISSING_MIN_MAC_LENGTH);
        short macLength =
            KMKeyParameters.findTag(data[KEY_PARAMETERS], KMType.UINT_TAG, KMType.MIN_MAC_LENGTH);
        macLength = KMIntegerTag.getValue(macLength);
        // Validate the MIN_MAC_LENGTH for AES - should be multiple of 8, less then 128 bits
        // and greater the 96 bits
        if (KMInteger.getSignificantShort(macLength) != 0
            || KMInteger.getShort(macLength) > 128
            || KMInteger.getShort(macLength) < 96
            || (KMInteger.getShort(macLength) % 8) != 0) {
          KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
        }
      }
    }
  }

  private void generateAESKey(byte[] scratchPad) {
    validateAESKey();
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    short len =
        seProvider.createSymmetricKey(KMType.AES, keysize, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  public void validateECKeys() {
    // Read key size
    short eccurve = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (!KMTag.isValidKeySize(data[KEY_PARAMETERS])) {
      if (eccurve == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      } else if (eccurve != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
  }

  private void generateECKeys(byte[] scratchPad) {
    validateECKeys();
    short[] lengths = tmpVariables;
    seProvider.createAsymmetricKey(KMType.EC, scratchPad, (short) 0, (short) 128, scratchPad,
        (short) 128,
        (short) 128, lengths);
    data[PUB_KEY] = KMByteBlob.instance(scratchPad, (short) 128, lengths[1]);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, lengths[0]);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateTDESKey() {
    if (!KMTag.isValidKeySize(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Minimum Mac length - it must not be present
    KMTag.assertAbsence(data[KEY_PARAMETERS], KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
        KMError.INVALID_TAG);
  }

  private void generateTDESKey(byte[] scratchPad) {
    validateTDESKey();
    short len = seProvider.createSymmetricKey(KMType.DES, (short) 168, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void validateHmacKey() {
    // If params does not contain any digest throw unsupported digest error.
    KMTag.assertPresence(data[KEY_PARAMETERS], KMType.ENUM_ARRAY_TAG, KMType.DIGEST,
        KMError.UNSUPPORTED_DIGEST);

    // check whether digest sizes are greater then or equal to min mac length.
    // Only SHA256 digest must be supported.
    if (KMEnumArrayTag.contains(KMType.DIGEST, KMType.DIGEST_NONE, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Read Minimum Mac length
    KMTag.assertPresence(data[KEY_PARAMETERS], KMType.UINT_TAG, KMType.MIN_MAC_LENGTH,
        KMError.MISSING_MIN_MAC_LENGTH);
    short minMacLength =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);

    if (((short) (minMacLength % 8) != 0)
        || minMacLength < (short) 64
        || minMacLength > (short) 256) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read Keysize
    if (!KMTag.isValidKeySize(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private void generateHmacKey(byte[] scratchPad) {
    validateHmacKey();
    short keysize = KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE,
        data[KEY_PARAMETERS]);
    // generate HMAC Key
    short len = seProvider.createSymmetricKey(KMType.HMAC, keysize, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void checkVersionAndPatchLevel(byte[] scratchPad) {
    short len =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    if (len != KMType.INVALID_VALUE) {
      short provOsVersion = readInteger32(KMDataStoreConstants.OS_VERSION, scratchPad, len);
      short status =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.getBuffer(provOsVersion),
              KMInteger.getStartOff(provOsVersion),
              scratchPad,
              (short) 0,
              len);
      if (status == -1) {
        // If the key characteristics has os version > current os version
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (status == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
    len =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    if (len != KMType.INVALID_VALUE) {
      short osPatch = readInteger32(KMDataStoreConstants.OS_PATCH_LEVEL, scratchPad, len);
      short status =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.getBuffer(osPatch),
              KMInteger.getStartOff(osPatch),
              scratchPad,
              (short) 0,
              len);
      if (status == -1) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (status == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
  }

  protected short getBootPatchLevel(byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, BOOT_PATCH_LVL_SIZE, (byte) 0);
    short len = bootParamsProv.getBootPatchLevel(scratchPad, (short) 0);
    if (len != BOOT_PATCH_LVL_SIZE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    return KMInteger.uint_32(scratchPad, (short) 0);
  }

  private void makeKeyCharacteristics(byte[] scratchPad) {
    data[KEY_CHARACTERISTICS] =
        makeKeyCharacteristics(
            data[KEY_PARAMETERS],
            readInteger32(KMDataStoreConstants.OS_VERSION, scratchPad, (short) 0),
            readInteger32(KMDataStoreConstants.OS_PATCH_LEVEL, scratchPad, (short) 0),
            readInteger32(KMDataStoreConstants.VENDOR_PATCH_LEVEL, scratchPad, (short) 0),
            getBootPatchLevel(scratchPad),
            data[ORIGIN],
            scratchPad);
    data[TEE_PARAMETERS] = KMKeyCharacteristics.getTeeEnforced(data[KEY_CHARACTERISTICS]);
    data[SW_PARAMETERS] = KMKeyCharacteristics.getKeystoreEnforced(data[KEY_CHARACTERISTICS]);
    data[SB_PARAMETERS] = KMKeyCharacteristics.getStrongboxEnforced(data[KEY_CHARACTERISTICS]);
    data[HW_PARAMETERS] = getHardwareParamters(data[SB_PARAMETERS], data[TEE_PARAMETERS]);
  }

  private void createEncryptedKeyBlob(byte[] scratchPad) {
    // make root of trust blob
    data[ROT] = readROT(scratchPad);
    if (data[ROT] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    // make hidden key params list
    data[HIDDEN_PARAMETERS] =
        KMKeyParameters.makeHidden(data[KEY_PARAMETERS], data[ROT], scratchPad);
    // make authorization data
    makeAuthData(scratchPad);
    // encrypt the secret and cryptographically attach that to authorization data
    encryptSecret(scratchPad);
    // create key blob array
    KMArray.add(data[KEY_BLOB], KEY_BLOB_SECRET, data[SECRET]);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_AUTH_TAG, data[AUTH_TAG]);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_NONCE, data[NONCE]);

    //TODO remove the following temporary creation of keyblob.
   /* short tempChar = KMKeyCharacteristics.instance();
    short emptyParam = KMArray.instance((short) 0);
    emptyParam = KMKeyParameters.instance(emptyParam);
    KMKeyCharacteristics.cast(tempChar).setStrongboxEnforced(data[SB_PARAMETERS]);
    KMKeyCharacteristics.cast(tempChar).setKeystoreEnforced(emptyParam);
    KMKeyCharacteristics.cast(tempChar).setTeeEnforced(data[TEE_PARAMETERS]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PARAMS, tempChar);*/
    short keyChars = makeKeyCharacteristicsForKeyblob(data[SW_PARAMETERS], data[SB_PARAMETERS],
        data[TEE_PARAMETERS]);
    KMArray.add(data[KEY_BLOB], KEY_BLOB_PARAMS, keyChars);

    // allocate reclaimable memory.
    short buffer = repository.alloc((short) 1024);
    short keyBlob = encoder.encode(data[KEY_BLOB], repository.getHeap(), buffer);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), buffer, keyBlob);
  }

  private short parseEncryptedKeyBlob(short keyBlob, short appId, short appData,
      byte[] scratchPad) {
    short parsedBlob = KMType.INVALID_VALUE;
    short rot = readROT(scratchPad);
    if (rot == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    try {
      parsedBlob = decoder.decodeArray(keyBlob(),
          KMByteBlob.getBuffer(keyBlob),
          KMByteBlob.getStartOff(keyBlob),
          KMByteBlob.length(keyBlob));
      if (KMArray.length(parsedBlob) < 4) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }

      // initialize data
      data[SECRET] = KMArray.get(parsedBlob, KEY_BLOB_SECRET);
      data[NONCE] = KMArray.get(parsedBlob, KEY_BLOB_NONCE);
      data[AUTH_TAG] = KMArray.get(parsedBlob, KEY_BLOB_AUTH_TAG);
      data[KEY_CHARACTERISTICS] = KMArray.get(parsedBlob, KEY_BLOB_PARAMS);
      data[PUB_KEY] = KMType.INVALID_VALUE;
      if (KMArray.length(parsedBlob) == 5) {
        data[PUB_KEY] = KMArray.get(parsedBlob, KEY_BLOB_PUB_KEY);
      }

      data[TEE_PARAMETERS] = KMKeyCharacteristics.getTeeEnforced(data[KEY_CHARACTERISTICS]);
      data[SB_PARAMETERS] = KMKeyCharacteristics.getStrongboxEnforced(data[KEY_CHARACTERISTICS]);
      data[SW_PARAMETERS] = KMKeyCharacteristics.getKeystoreEnforced(data[KEY_CHARACTERISTICS]);
      data[HW_PARAMETERS] = getHardwareParamters(data[SB_PARAMETERS], data[TEE_PARAMETERS]);

      data[HIDDEN_PARAMETERS] = KMKeyParameters.makeHidden(appId, appData, rot, scratchPad);
      data[KEY_BLOB] = parsedBlob;
      // make auth data
      makeAuthData(scratchPad);
      // Decrypt Secret and verify auth tag
      decryptSecret(scratchPad);
      KMArray.add(parsedBlob, KEY_BLOB_SECRET, data[SECRET]);
    } catch (Exception e) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    return parsedBlob;
  }

  // Read RoT
  public short readROT(byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    short len = bootParamsProv.getBootKey(scratchPad, (short) 0);
    len += bootParamsProv.getVerifiedBootHash(scratchPad, (short) len);
    short bootState = bootParamsProv.getBootState();
    len = Util.setShort(scratchPad, len, bootState);
    if (bootParamsProv.isDeviceBootLocked()) {
      scratchPad[len] = (byte) 1;
    } else {
      scratchPad[len] = (byte) 0;
    }
    len++;
    return KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  private void decryptSecret(byte[] scratchPad) {
    // derive master key - stored in derivedKey
    short len = deriveKey(scratchPad);
    if (!seProvider.aesGCMDecrypt(
        KMByteBlob.getBuffer(data[DERIVED_KEY]),
        KMByteBlob.getStartOff(data[DERIVED_KEY]),
        KMByteBlob.length(data[DERIVED_KEY]),
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        scratchPad, (short) 0,
        KMByteBlob.getBuffer(data[NONCE]),
        KMByteBlob.getStartOff(data[NONCE]),
        KMByteBlob.length(data[NONCE]),
        repository.getHeap(), data[AUTH_DATA], data[AUTH_DATA_LENGTH],
        KMByteBlob.getBuffer(data[AUTH_TAG]),
        KMByteBlob.getStartOff(data[AUTH_TAG]),
        KMByteBlob.length(data[AUTH_TAG]))) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Copy the decrypted secret
    data[SECRET] =
        KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.length(data[SECRET]));
  }

  private void encryptSecret(byte[] scratchPad) {
    // make nonce
    data[NONCE] = KMByteBlob.instance((short) AES_GCM_NONCE_LENGTH);
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    Util.arrayCopyNonAtomic(
        KMByteBlob.getBuffer(data[NONCE]),
        KMByteBlob.getStartOff(data[NONCE]),
        scratchPad,
        (short) 0,
        KMByteBlob.length(data[NONCE]));
    seProvider.newRandomNumber(
        KMByteBlob.getBuffer(data[NONCE]),
        KMByteBlob.getStartOff(data[NONCE]),
        KMByteBlob.length(data[NONCE]));
    // derive master key - stored in derivedKey
    short len = deriveKey(scratchPad);
    len = seProvider.aesGCMEncrypt(
        KMByteBlob.getBuffer(data[DERIVED_KEY]),
        KMByteBlob.getStartOff(data[DERIVED_KEY]),
        KMByteBlob.length(data[DERIVED_KEY]),
        KMByteBlob.getBuffer(data[SECRET]),
        KMByteBlob.getStartOff(data[SECRET]),
        KMByteBlob.length(data[SECRET]),
        scratchPad,
        (short) 0,
        KMByteBlob.getBuffer(data[NONCE]),
        KMByteBlob.getStartOff(data[NONCE]),
        KMByteBlob.length(data[NONCE]),
        repository.getHeap(),
        data[AUTH_DATA],
        data[AUTH_DATA_LENGTH],
        KMByteBlob.getBuffer(data[AUTH_TAG]),
        KMByteBlob.getStartOff(data[AUTH_TAG]),
        KMByteBlob.length(data[AUTH_TAG]));

    if (len > 0 && len != KMByteBlob.length(data[SECRET])) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, len);
  }

  private void makeAuthData(byte[] scratchPad) {
    /*short arrayLen = 2;
    if (KMArray.cast(data[KEY_BLOB]).length() == 5) {
      arrayLen = 3;
    }
    short params = KMArray.instance((short) arrayLen);
    KMArray.cast(params).add((short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
   // KMArray.cast(params).add((short) 1, KMKeyParameters.cast(data[SW_PARAMETERS]).getVals());
    KMArray.cast(params).add((short) 1, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
    if (3 == arrayLen) {
      KMArray.cast(params).add((short) 2, data[PUB_KEY]);
    }*/
    short params =
        concatParamsForAuthData(data[KEY_BLOB], data[HW_PARAMETERS],
            data[SW_PARAMETERS], data[HIDDEN_PARAMETERS], data[PUB_KEY]);

    short authIndex = repository.alloc(MAX_AUTH_DATA_SIZE);
    short index = 0;
    short len = 0;
    short paramsLen = KMArray.length(params);
    Util.arrayFillNonAtomic(repository.getHeap(), authIndex, (short) MAX_AUTH_DATA_SIZE, (byte) 0);
    while (index < paramsLen) {
      short tag = KMArray.get(params, index);
      len = encoder.encode(tag, repository.getHeap(), (short) (authIndex + 32));
      Util.arrayCopyNonAtomic(repository.getHeap(), (short) authIndex, repository.getHeap(),
          (short) (authIndex + len + 32), (short) 32);
      len = seProvider.messageDigest256(repository.getHeap(),
          (short) (authIndex + 32), (short) (len + 32), repository.getHeap(), (short) authIndex);
      if (len != 32) {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      index++;
    }
    data[AUTH_DATA] = authIndex;
    data[AUTH_DATA_LENGTH] = len;
  }

  private short deriveKey(byte[] scratchPad) {
    // KeyDerivation:
    // 1. Do HMAC Sign, Auth data.
    // 2. HMAC Sign generates an output of 32 bytes length.
    // Consume only first 16 bytes as derived key.
    // Hmac sign.
    short len = seProvider.hmacKDF(
        storeDataInst.getMasterKey(),
        repository.getHeap(),
        data[AUTH_DATA],
        data[AUTH_DATA_LENGTH],
        scratchPad,
        (short) 0);
    if (len < 16) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = 16;
    data[DERIVED_KEY] = KMByteBlob.instance(scratchPad, (short) 0, len);
    return len;
  }

  public void sendError(APDU apdu, short err) {
    short resp = KMArray.instance((short) 1);
    err = KMError.translate(err);
    short error = KMInteger.uint_16(err);
    KMArray.add(resp, (short) 0, error);
    sendOutgoing(apdu, resp);
  }

  private short addIntegers(short authTime, short timeStamp, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.getBuffer(authTime),
        KMInteger.getStartOff(authTime),
        scratchPad,
        (short) (8 - KMInteger.length(timeStamp)),
        KMInteger.length(timeStamp));

    // Copy timestamp to scratchpad
    Util.arrayCopyNonAtomic(
        KMInteger.getBuffer(timeStamp),
        KMInteger.getStartOff(timeStamp),
        scratchPad,
        (short) (16 - KMInteger.length(timeStamp)),
        KMInteger.length(timeStamp));

    // add authTime in millis to timestamp.
    KMUtils.add(scratchPad, (short) 0, (short) 8, (short) 16);
    return KMInteger.uint_64(scratchPad, (short) 16);
  }

  public void powerReset() {
    releaseAllOperations();
    resetWrappingKey();
  }

  public void generateRkpKey(byte[] scratchPad, short keyParams) {
    data[KEY_PARAMETERS] = keyParams;
    generateECKeys(scratchPad);
    // create key blob
    data[ORIGIN] = KMType.GENERATED;
    makeKeyCharacteristics(scratchPad);
    createEncryptedKeyBlob(scratchPad);
  }

  public static short getPubKey() {
    return data[PUB_KEY];
  }

  public static short getPivateKey() {
    return data[KEY_BLOB];
  }

  /**
   * Encodes the object to the provided apdu buffer.
   *
   * @param object Object to be encoded.
   * @param apduBuf Buffer on which the encoded data is copied.
   * @param apduOff Start offset of the buffer.
   * @param maxLen Max value of the expected out length.
   * @return length of the encoded buffer.
   */
  public short encodeToApduBuffer(short object, byte[] apduBuf, short apduOff,
      short maxLen) {
    short offset = repository.allocReclaimableMemory(maxLen);
    short len = encoder.encode(object, repository.getHeap(), offset);
    Util.arrayCopyNonAtomic(repository.getHeap(), offset, apduBuf, apduOff, len);
    //release memory
    repository.reclaimMemory(maxLen);
    return len;
  }


  private void updateTrustedConfirmationOperation(KMOperationState op) {
    if (op.isTrustedConfirmationRequired()) {
      op.getTrustedConfirmationSigner().update(KMByteBlob.getBuffer(data[INPUT_DATA]),
          KMByteBlob.getStartOff(data[INPUT_DATA]), KMByteBlob.length(data[INPUT_DATA]));
    }
  }

  private void finishTrustedConfirmationOperation(KMOperationState op) {
    // Perform trusted confirmation if required
    if (op.isTrustedConfirmationRequired()) {
      short confToken = getConfirmationToken(data[CONFIRMATION_TOKEN], data[KEY_PARAMETERS]);
      boolean verified = op.getTrustedConfirmationSigner()
          .verify(KMByteBlob.getBuffer(data[INPUT_DATA]),
              KMByteBlob.getStartOff(data[INPUT_DATA]), KMByteBlob.length(data[INPUT_DATA]),
              KMByteBlob.getBuffer(confToken),
              KMByteBlob.getStartOff(confToken),
              KMByteBlob.length(confToken));
      if (!verified) {
        KMException.throwIt(KMError.NO_USER_CONFIRMATION);
      }
    }
  }

  public short getHardwareInfo() {
    short respPtr = KMArray.instance((short) 4);
    KMArray.add(respPtr, (short) 0, buildErrorStatus(KMError.OK));
    KMArray.add(respPtr, (short) 1, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    KMArray.add(respPtr,
        (short) 2,
        KMByteBlob.instance(
            JAVACARD_KEYMASTER_DEVICE, (short) 0, (short) JAVACARD_KEYMASTER_DEVICE.length));
    KMArray.add(respPtr, (short) 3, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));
    return respPtr;
  }

  public short makeKeyCharacteristics(short keyParams, short osVersion, short osPatch,
      short vendorPatch, short bootPatch, short origin, byte[] scratchPad) {
    short strongboxParams = KMKeyParameters.makeSbEnforced(
        keyParams, (byte) origin, osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    short teeParams = KMKeyParameters.makeTeeEnforced(keyParams, scratchPad);
    short swParams = KMKeyParameters.makeKeystoreEnforced(keyParams, scratchPad);
    short hwParams = KMKeyParameters.makeHwEnforced(strongboxParams, teeParams);
    short arr = KMArray.instance((short) 0);
    short emptyParams = KMKeyParameters.instance(arr);
    short keyCharacteristics = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.setStrongboxEnforced(keyCharacteristics, hwParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyCharacteristics, swParams);
    KMKeyCharacteristics.setTeeEnforced(keyCharacteristics, emptyParams);
    return keyCharacteristics;
  }

  public short makeKeyCharacteristicsForKeyblob(short swParams, short sbParams, short teeParams) {
    short keyChars = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.setStrongboxEnforced(keyChars, sbParams);
    KMKeyCharacteristics.setKeystoreEnforced(keyChars, swParams);
    KMKeyCharacteristics.setTeeEnforced(keyChars, teeParams);
    return keyChars;
  }

  public short getKeyCharacteristicsExp() {
    return KMKeyCharacteristics.exp();
  }

  public void validateEarlyBoot(short Params, byte inst, byte[] sPad, short sPadOff,
      short errorCode) {

    // As per specification, Early boot keys may not be imported at all, if Tag::EARLY_BOOT_ONLY is
    // provided to IKeyMintDevice::importKey
    if (inst == INS_IMPORT_KEY_CMD || readBoolean(KMDataStoreConstants.EARLY_BOOT_ENDED_STATUS,
        sPad, sPadOff)) {
      // Validate early boot
      KMTag.assertAbsence(Params, KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, errorCode);
    }
  }

  public short getHardwareParamters(short sbParams, short teeParams) {
    return sbParams;
  }

  public short concatParamsForAuthData(short keyBlobPtr, short hwParams, short swParams,
      short hiddenParams, short pubKey) {
    short arrayLen = 3;
    if (pubKey != KMType.INVALID_VALUE) {
      arrayLen = 4;
    }
    short params = KMArray.instance((short) arrayLen);
    KMArray.add(params, (short) 0, KMKeyParameters.getVals(hwParams));
    KMArray.add(params, (short) 1, KMKeyParameters.getVals(swParams));
    KMArray.add(params, (short) 2, KMKeyParameters.getVals(hiddenParams));
    if (4 == arrayLen) {
      KMArray.add(params, (short) 3, pubKey);
    }
    return params;
  }

  public short getSupportedAttestationMode(short attChallenge) {
    return KMType.FACTORY_PROVISIONED_ATTEST_CERT;
  }

  public KMAttestationCert makeCommonCert(short swParams, short hwParams, short keyParams,
      byte[] scratchPad, KMSEProvider seProvider) {
    boolean rsaCert = (KMEnumTag.getValue(KMType.ALGORITHM, hwParams) == KMType.RSA);
    KMAttestationCert cert = KMAttestationCertImpl.instance(rsaCert, seProvider);
    // notBefore
    short notBefore =
        KMKeyParameters.findTag(swParams, KMType.DATE_TAG, KMType.ACTIVE_DATETIME);
    if (notBefore == KMType.INVALID_VALUE) {
      notBefore =
          KMKeyParameters.findTag(swParams, KMType.DATE_TAG, KMType.CREATION_DATETIME);
      if (notBefore == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
    }
    notBefore = KMIntegerTag.getValue(notBefore);
    cert.notBefore(notBefore, false, scratchPad);
    // notAfter
    // expiry time - byte blob
    boolean derEncoded = false;
    short notAfter =
        KMKeyParameters.findTag(swParams, KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME);
    if (notAfter == KMType.INVALID_VALUE) {
      notAfter = getProvisionedCertificateData(seProvider, KMDataStoreConstants.CERTIFICATE_EXPIRY);
      derEncoded = true;
    }
    cert.notAfter(notAfter, derEncoded, scratchPad);
    // SubjectName
    cert.subjectName(KMByteBlob.instance(X509Subject, (short) 0, (short) X509Subject.length));
    // Serial
    short serialNumber = KMByteBlob.instance((short) 1);
    KMByteBlob.add(serialNumber, (short) 0, SERIAL_NUM);
    cert.serialNumber(serialNumber);
    // Issuer.
    cert.issuer(getProvisionedCertificateData(seProvider, KMDataStoreConstants.CERTIFICATE_ISSUER));
    return cert;
  }

  private short getProvisionedCertificateData(KMSEProvider kmseProvider, byte dataType) {
    short len = storeDataInst.getCertificateDataLength(dataType);
    if (len == 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short ptr = KMByteBlob.instance(len);
    storeDataInst.readCertificateData(
        dataType,
        KMByteBlob.getBuffer(ptr),
        KMByteBlob.getStartOff(ptr));
    return ptr;
  }

  public short getConfirmationToken(short confToken, short keyParams) {
    short cToken =
        KMKeyParameters.findTag(keyParams, KMType.BYTES_TAG, KMType.CONFIRMATION_TOKEN);
    if (cToken == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.NO_USER_CONFIRMATION);
    }
    return KMByteTag.getValue(cToken);
  }

  public short getKMVerificationTokenExp() {
    return KMVerificationToken.verificationTokenExp();
  }

  public short getMacFromVerificationToken(short verToken) {
    return KMVerificationToken.getMac(verToken, (short) 0x04);
  }

  public short getMgf1Digest(short keyParams, short hwParams) {
    return KMType.SHA1;
  }

  //This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  public short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (seProvider.isPowerReset(true)) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }
    Util.setShort(KMInteger.getBuffer(int32Ptr),
        KMInteger.getStartOff(int32Ptr),
        powerResetStatus);

    Util.setShort(KMInteger.getBuffer(int32Ptr),
        (short) (KMInteger.getStartOff(int32Ptr) + 2),
        err);
    return int32Ptr;
  }

  public short generateAttestKeyExp() {
    // Arguments
    short keyParams = KMKeyParameters.expAny();
    short keyBlob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 2);
    KMArray.add(argsProto, (short) 0, keyBlob);
    KMArray.add(argsProto, (short) 1, keyParams);
    return argsProto;
  }

  public void getAttestKeyInputParameters(short arrPtr, short[] data, byte keyBlobOff,
      byte keyParametersOff,
      byte attestKeyBlobOff, byte attestKeyParamsOff, byte attestKeyIssuerOff) {
    data[keyBlobOff] = KMArray.get(arrPtr, (short) 0);
    data[keyParametersOff] = KMArray.get(arrPtr, (short) 1);
    data[attestKeyBlobOff] = KMType.INVALID_VALUE;
    data[attestKeyParamsOff] = KMType.INVALID_VALUE;
    data[attestKeyIssuerOff] = KMType.INVALID_VALUE;
  }

  public short prepareBeginResp(short paramsPtr, short opHandlePtr, short bufModPtr,
      short macLengthPtr) {
    short resp = KMArray.instance((short) 3);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, paramsPtr);
    KMArray.add(resp, (short) 2, opHandlePtr);
    return resp;
  }

  public short prepareFinishExp() {
    short byteBlob = KMByteBlob.exp();
    short cmd = KMArray.instance((short) 6);
    KMArray.add(cmd, (short) 0, KMInteger.exp());//op handle
    short keyParam = KMKeyParameters.exp();
    KMArray.add(cmd, (short) 1, keyParam);// Key Parameters
    KMArray.add(cmd, (short) 2, byteBlob);// input data
    KMArray.add(cmd, (short) 3, byteBlob); // signature
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 4, authToken); // auth token
    short verToken = getKMVerificationTokenExp();
    KMArray.add(cmd, (short) 5, verToken); // time stamp token
    return cmd;
  }

  public short prepareUpdateExp() {
    short cmd = KMArray.instance((short) 5);
    // Arguments
    short keyParams = KMKeyParameters.exp();
    KMArray.add(cmd, (short) 0, KMInteger.exp());
    KMArray.add(cmd, (short) 1, keyParams);
    KMArray.add(cmd, (short) 2, KMByteBlob.exp());
    short authToken = KMHardwareAuthToken.exp();
    KMArray.add(cmd, (short) 3, authToken);
    short verToken = getKMVerificationTokenExp();
    KMArray.add(cmd, (short) 4, verToken);
    return cmd;
  }

  public void getUpdateInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte hwTokenOff,
      byte verToken) {
    data[opHandleOff] = KMArray.get(arrPtr, (short) 0);
    data[keyParametersOff] = KMArray.get(arrPtr, (short) 1);
    data[inputDataOff] = KMArray.get(arrPtr, (short) 2);
    data[hwTokenOff] = KMArray.get(arrPtr, (short) 3);
    data[verToken] = KMArray.get(arrPtr, (short) 4);
  }

  public void getFinishInputParameters(short arrPtr, short[] data, byte opHandleOff,
      byte keyParametersOff, byte inputDataOff, byte signDataOff, byte hwTokenOff, byte verToken,
      byte confToken) {
    data[opHandleOff] = KMArray.get(arrPtr, (short) 0);
    data[keyParametersOff] = KMArray.get(arrPtr, (short) 1);
    data[inputDataOff] = KMArray.get(arrPtr, (short) 2);
    data[signDataOff] = KMArray.get(arrPtr, (short) 3);
    data[hwTokenOff] = KMArray.get(arrPtr, (short) 4);
    data[verToken] = KMArray.get(arrPtr, (short) 5);
    data[confToken] = KMType.INVALID_VALUE;
  }

  public short prepareFinishResp(short outputPtr) {
    short keyParam = KMArray.instance((short) 0);
    keyParam = KMKeyParameters.instance(keyParam);
    short resp = KMArray.instance((short) 3);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, keyParam);
    KMArray.add(resp, (short) 2, outputPtr);
    return resp;
  }

  public short prepareUpdateResp(short outputPtr, short inputConsumedPtr) {
    short resp = KMArray.instance((short) 4);
    KMArray.add(resp, (short) 0, KMInteger.uint_16(KMError.OK));
    KMArray.add(resp, (short) 1, inputConsumedPtr);
    short keyParm = KMKeyParameters.instance(KMArray.instance((short) 0));
    KMArray.add(resp, (short) 2, keyParm);
    KMArray.add(resp, (short) 3, outputPtr);
    return resp;
  }

  public void validateP1P2(APDU apdu) {
    byte[] apduBuffer = apdu.getBuffer();
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
    // Validate P1P2.
    if (P1P2 != KEYMASTER_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  public boolean isAssociatedDataTagSupported() {
    return true;
  }

  void assertPrivateOperation(short purpose, short algorithm) {
    switch (algorithm) {
      case KMType.RSA:
        if (purpose == KMType.ENCRYPT || purpose == KMType.VERIFY) {
          KMException.throwIt(KMError.PUBLIC_KEY_OPERATION);
        }
        break;
      case KMType.EC:
        if (purpose == KMType.VERIFY) {
          KMException.throwIt(KMError.PUBLIC_KEY_OPERATION);
        }
        break;
      default:
        break;
    }
  }
}
