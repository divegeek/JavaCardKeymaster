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

package com.android.javacard.keymaster;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AppletEvent;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacardx.apdu.ExtendedLength;

/**
 * KMKeymasterApplet implements the javacard applet. It creates repository and other install time
 * objects. It also implements the keymaster state machine and handles javacard applet life cycle
 * events.
 */
public class KMKeymasterApplet extends Applet implements AppletEvent, ExtendedLength {

  // Constants.
  public static final byte AES_BLOCK_SIZE = 16;
  public static final byte DES_BLOCK_SIZE = 8;
  public static final short MAX_LENGTH = (short) 0x2000;
  private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  private static final short KM_HAL_VERSION = (short) 0x4000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  private static final short DERIVE_KEY_INPUT_SIZE = (short) 256;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;

  // "Keymaster HMAC Verification" - used for HMAC key verification.
  public static final byte[] sharingCheck = {
      0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x48, 0x4D, 0x41, 0x43, 0x20,
      0x56,
      0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E
  };
  // "KeymasterSharedMac"
  public static final byte[] ckdfLable = {
      0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x53, 0x68, 0x61, 0x72, 0x65, 0x64,
      0x4D,
      0x61, 0x63
  };
  // "Auth Verification"
  public static final byte[] authVerification = {
      0x41, 0x75, 0x74, 0x68, 0x20, 0x56, 0x65, 0x72, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x69,
      0x6F,
      0x6E
  };
  // "confirmation token"
  public static final byte[] confirmationToken = {
      0x63, 0x6F, 0x6E, 0x66, 0x69, 0x72, 0x6D, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x6F,
      0x6B,
      0x65, 0x6E
  };

  // Possible states of the applet.
  private static final byte KM_BEGIN_STATE = 0x00;
  private static final byte ILLEGAL_STATE = KM_BEGIN_STATE + 1;
  private static final byte INIT_STATE = KM_BEGIN_STATE + 2;
  private static final byte IN_PROVISION_STATE = KM_BEGIN_STATE + 3;
  private static final byte ACTIVE_STATE = KM_BEGIN_STATE + 4;

  // Commands
  private static final byte INS_BEGIN_KM_CMD = 0x00;
  // Instructions for Provision Commands.
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD = INS_BEGIN_KM_CMD + 2; //0x02
  private static final byte INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD = INS_BEGIN_KM_CMD + 3; //0x03
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD + 4; //0x04
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD = INS_BEGIN_KM_CMD + 5; //0x05
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_BEGIN_KM_CMD + 6; //0x06
  private static final byte INS_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 7; //0x07
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD + 8; //0x08
  private static final byte INS_SET_VERSION_PATCHLEVEL_CMD = INS_BEGIN_KM_CMD + 9; //0x09
  // Top 32 commands are reserved for provisioning.
  private static final byte INS_END_KM_PROVISION_CMD = 0x20;

  private static final byte INS_GENERATE_KEY_CMD = INS_END_KM_PROVISION_CMD + 1;  //0x21
  private static final byte INS_IMPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 2;    //0x22
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = INS_END_KM_PROVISION_CMD + 3; //0x23
  private static final byte INS_EXPORT_KEY_CMD = INS_END_KM_PROVISION_CMD + 4; //0x24
  private static final byte INS_ATTEST_KEY_CMD = INS_END_KM_PROVISION_CMD + 5; //0x25
  private static final byte INS_UPGRADE_KEY_CMD = INS_END_KM_PROVISION_CMD + 6; //0x26
  private static final byte INS_DELETE_KEY_CMD = INS_END_KM_PROVISION_CMD + 7; //0x27
  private static final byte INS_DELETE_ALL_KEYS_CMD = INS_END_KM_PROVISION_CMD + 8; //0x28
  private static final byte INS_ADD_RNG_ENTROPY_CMD = INS_END_KM_PROVISION_CMD + 9; //0x29
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = INS_END_KM_PROVISION_CMD + 10; //0x2A
  private static final byte INS_DESTROY_ATT_IDS_CMD = INS_END_KM_PROVISION_CMD + 11;  //0x2B
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = INS_END_KM_PROVISION_CMD + 12; //0x2C
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = INS_END_KM_PROVISION_CMD + 13; //0x2D
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = INS_END_KM_PROVISION_CMD + 14; //0x2E
  private static final byte INS_GET_HW_INFO_CMD = INS_END_KM_PROVISION_CMD + 15; //0x2F
  private static final byte INS_BEGIN_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 16;  //0x30
  private static final byte INS_UPDATE_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 17;  //0x31
  private static final byte INS_FINISH_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 18; //0x32
  private static final byte INS_ABORT_OPERATION_CMD = INS_END_KM_PROVISION_CMD + 19; //0x33
  private static final byte INS_DEVICE_LOCKED_CMD = INS_END_KM_PROVISION_CMD + 20;//0x34
  private static final byte INS_EARLY_BOOT_ENDED_CMD = INS_END_KM_PROVISION_CMD + 21; //0x35
  private static final byte INS_GET_CERT_CHAIN_CMD = INS_END_KM_PROVISION_CMD + 22; //0x36

  private static final byte INS_END_KM_CMD = 0x7F;

  // Provision reporting status
  private static final byte NOT_PROVISIONED = 0x00;
  private static final byte PROVISION_STATUS_ATTESTATION_KEY = 0x01;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04;
  private static final byte PROVISION_STATUS_ATTEST_IDS = 0x08;
  private static final byte PROVISION_STATUS_PRESHARED_SECRET = 0x10;
  private static final byte PROVISION_STATUS_BOOT_PARAM = 0x20;
  private static final byte PROVISION_STATUS_PROVISIONING_LOCKED = 0x40;

  // Data Dictionary items
  public static final byte DATA_ARRAY_SIZE = 30;
  public static final byte TMP_VARIABLE_ARRAY_SIZE = 20;
  public static final byte UPDATE_PARAM_ARRAY_SIZE = 40;
  public static final byte KEY_PARAMETERS = 0;
  public static final byte KEY_CHARACTERISTICS = 1;
  public static final byte HIDDEN_PARAMETERS = 2;
  public static final byte HW_PARAMETERS = 3;
  public static final byte SW_PARAMETERS = 4;
  public static final byte AUTH_DATA = 5;
  public static final byte AUTH_TAG = 6;
  public static final byte NONCE = 7;
  public static final byte KEY_BLOB = 8;
  public static final byte AUTH_DATA_LENGTH = 9;
  public static final byte SECRET = 10;
  public static final byte ROT = 11;
  public static final byte DERIVED_KEY = 12;
  public static final byte RSA_PUB_EXPONENT = 13;
  public static final byte APP_ID = 14;
  public static final byte APP_DATA = 15;
  public static final byte PUB_KEY = 16;
  public static final byte IMPORTED_KEY_BLOB = 17;
  public static final byte ORIGIN = 18;
  public static final byte ENC_TRANSPORT_KEY = 19;
  public static final byte MASKING_KEY = 20;
  public static final byte HMAC_SHARING_PARAMS = 21;
  public static final byte OP_HANDLE = 22;
  public static final byte IV = 23;
  public static final byte INPUT_DATA = 24;
  public static final byte OUTPUT_DATA = 25;
  public static final byte HW_TOKEN = 26;
  public static final byte VERIFICATION_TOKEN = 27;
  public static final byte SIGNATURE = 28;

  // AddRngEntropy
  protected static final short MAX_SEED_SIZE = 2048;
  // Keyblob constants
  public static final byte KEY_BLOB_SECRET = 0;
  public static final byte KEY_BLOB_NONCE = 1;
  public static final byte KEY_BLOB_AUTH_TAG = 2;
  public static final byte KEY_BLOB_KEYCHAR = 3;
  public static final byte KEY_BLOB_PUB_KEY = 4;
  // AES GCM constants
  private static final byte AES_GCM_AUTH_TAG_LENGTH = 16;
  private static final byte AES_GCM_NONCE_LENGTH = 12;
  // ComputeHMAC constants
  private static final short HMAC_SHARED_PARAM_MAX_SIZE = 64;
  // Maximum certificate size.
  private static final short MAX_CERT_SIZE = 2048;
  // Buffer constants.
  private static final short BUF_START_OFFSET = 0;
  private static final short BUF_LEN_OFFSET = 2;

  // Keymaster Applet attributes
  protected static byte keymasterState = ILLEGAL_STATE;
  protected static KMEncoder encoder;
  protected static KMDecoder decoder;
  protected static KMRepository repository;
  protected static KMSEProvider seProvider;
  protected static Object[] bufferRef;
  protected static short[] bufferProp;
  protected static short[] tmpVariables;
  protected static short[] data;
  protected static byte provisionStatus = NOT_PROVISIONED;

  /**
   * Registers this applet.
   */
  protected KMKeymasterApplet(KMSEProvider seImpl) {
    seProvider = seImpl;
    boolean isUpgrading = seImpl.isUpgrading();
    repository = new KMRepository(isUpgrading);
    initializeTransientArrays();
    if (!isUpgrading) {
      keymasterState = KMKeymasterApplet.INIT_STATE;
      seProvider.createMasterKey((short) (KMRepository.MASTER_KEY_SIZE * 8));
    }
    KMType.initialize();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
  }

  private void initializeTransientArrays() {
    data = JCSystem.makeTransientShortArray((short) DATA_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferRef = JCSystem.makeTransientObjectArray((short) 1, JCSystem.CLEAR_ON_RESET);
    bufferProp = JCSystem.makeTransientShortArray((short) 4, JCSystem.CLEAR_ON_RESET);
    tmpVariables =
        JCSystem.makeTransientShortArray((short) TMP_VARIABLE_ARRAY_SIZE, JCSystem.CLEAR_ON_RESET);
    bufferProp[BUF_START_OFFSET] = 0;
    bufferProp[BUF_LEN_OFFSET] = 0;
  }

  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
    repository.onSelect();
    if (keymasterState == KMKeymasterApplet.INIT_STATE) {
      keymasterState = KMKeymasterApplet.IN_PROVISION_STATE;
    }
    return true;
  }

  /**
   * De-selects this applet.
   */
  @Override
  public void deselect() {
    repository.onDeselect();
  }

  /**
   * Uninstalls the applet after cleaning the repository.
   */
  @Override
  public void uninstall() {
    repository.onUninstall();
  }

  private short mapISOErrorToKMError(short reason) {
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

  private short mapCryptoErrorToKMError(short reason) {
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

  protected void validateApduHeader(APDU apdu) {
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // Validate P1P2.
    if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   *
   * @param apdu the incoming APDU
   */
  @Override
  public void process(APDU apdu) {
    try {
      // Handle the card reset status before processing apdu.
      if (repository.isPowerResetEventOccurred()) {
        // Release all the operation instances.
        seProvider.releaseAllOperations();
      }
      repository.onProcess();
      // Verify whether applet is in correct state.
      if ((keymasterState == KMKeymasterApplet.INIT_STATE)
          || (keymasterState == KMKeymasterApplet.ILLEGAL_STATE)) {
        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
      }
      // If this is select applet apdu which is selecting this applet then
      // return
      if (apdu.isISOInterindustryCLA()) {
        if (selectingApplet()) {
          return;
        }
      }
      // Validate APDU Header.
      validateApduHeader(apdu);

      byte[] apduBuffer = apdu.getBuffer();
      byte apduIns = apduBuffer[ISO7816.OFFSET_INS];

      // Validate whether INS can be supported
      if (!(apduIns > INS_BEGIN_KM_CMD && apduIns < INS_END_KM_CMD)) {
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }
      bufferRef[0] = repository.getHeap();
      // Process the apdu
      if (keymasterState == KMKeymasterApplet.IN_PROVISION_STATE) {
        switch (apduIns) {
          case INS_PROVISION_ATTESTATION_KEY_CMD:
            processProvisionAttestationKey(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_KEY;
            sendError(apdu, KMError.OK);
            return;

          case INS_PROVISION_ATTESTATION_CERT_CHAIN_CMD:
            processProvisionAttestationCertChainCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_CERT_CHAIN;
            sendError(apdu, KMError.OK);
            return;

          case INS_PROVISION_ATTESTATION_CERT_PARAMS_CMD:
            processProvisionAttestationCertParams(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_CERT_PARAMS;
            sendError(apdu, KMError.OK);
            return;

          case INS_PROVISION_ATTEST_IDS_CMD:
            processProvisionAttestIdsCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTEST_IDS;
            sendError(apdu, KMError.OK);
            return;

          case INS_PROVISION_PRESHARED_SECRET_CMD:
            processProvisionSharedSecretCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_PRESHARED_SECRET;
            sendError(apdu, KMError.OK);
            return;

          case INS_LOCK_PROVISIONING_CMD:
            if (isProvisioningComplete()) {
              provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_PROVISIONING_LOCKED;
              keymasterState = KMKeymasterApplet.ACTIVE_STATE;
              sendError(apdu, KMError.OK);
            } else {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            return;
        }
      }

      if ((keymasterState == KMKeymasterApplet.ACTIVE_STATE)
          || (keymasterState == KMKeymasterApplet.IN_PROVISION_STATE)) {
        switch (apduIns) {
          case INS_SET_BOOT_PARAMS_CMD:
            if (seProvider.isBootSignalEventSupported()
                && (keymasterState == KMKeymasterApplet.ACTIVE_STATE)
                && (!seProvider.isDeviceRebooted())) {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            processSetBootParamsCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_BOOT_PARAM;
            seProvider.clearDeviceBooted(false);
            sendError(apdu, KMError.OK);
            return;

          case INS_GET_PROVISION_STATUS_CMD:
            processGetProvisionStatusCmd(apdu);
            return;
        }
      }

      if ((keymasterState == KMKeymasterApplet.ACTIVE_STATE)
          || ((keymasterState == KMKeymasterApplet.IN_PROVISION_STATE)
          && isProvisioningComplete())) {
        switch (apduIns) {
          case INS_GENERATE_KEY_CMD:
            processGenerateKey(apdu);
            break;
          case INS_IMPORT_KEY_CMD:
            processImportKeyCmd(apdu);
            break;
          case INS_IMPORT_WRAPPED_KEY_CMD:
            processImportWrappedKeyCmd(apdu);
            break;
          case INS_EXPORT_KEY_CMD:
            processExportKeyCmd(apdu);
            break;
          case INS_ATTEST_KEY_CMD:
            processAttestKeyCmd(apdu);
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
          case INS_GET_CERT_CHAIN_CMD:
            processGetCertChainCmd(apdu);
            break;
          case INS_SET_VERSION_PATCHLEVEL_CMD:
            processSetVersionAndPatchLevels(apdu);
            break;
          default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
      } else {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
    } catch (KMException exception) {
      freeOperations();
      sendError(apdu, KMException.getReason());
      exception.clear();
    } catch (ISOException exp) {
      sendError(apdu, mapISOErrorToKMError(exp.getReason()));
      freeOperations();
    } catch (CryptoException e) {
      freeOperations();
      sendError(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      freeOperations();
      sendError(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      resetData();
      repository.clean();
    }
  }

  private void generateUniqueOperationHandle(byte[] buf, short offset, short len) {
    do {
      seProvider.newRandomNumber(buf, offset, len);
    } while (null != repository.findOperation(buf, offset, len));
  }

  private boolean isProvisioningComplete() {
    if ((0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_KEY))
        && (0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_CERT_CHAIN))
        && (0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_CERT_PARAMS))
        && (0 != (provisionStatus & PROVISION_STATUS_PRESHARED_SECRET))) {
      return true;
    } else {
      return false;
    }
  }

  private void freeOperations() {
    if (data[OP_HANDLE] != KMType.INVALID_VALUE) {
      KMOperationState op = repository.findOperation(data[OP_HANDLE]);
      if (op != null) {
        repository.releaseOperation(op);
      }
    }
  }

  private void processEarlyBootEndedCmd(APDU apdu) {
    KMException.throwIt(KMError.UNIMPLEMENTED);
  }

  private void processDeviceLockedCmd(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMInteger.exp());
    tmpVariables[1] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    tmpVariables[1] = KMArray.cast(tmpVariables[0]).get((short) 0);
    tmpVariables[1] = KMInteger.cast(tmpVariables[1]).getByte();
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[0]).get((short) 1);
    validateVerificationToken(data[VERIFICATION_TOKEN], scratchPad);
    short verTime = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
    short lastDeviceLockedTime = repository.getDeviceTimeStamp();
    if (KMInteger.compare(verTime, lastDeviceLockedTime) > 0) {
      Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 8, (byte) 0);
      KMInteger.cast(verTime).getValue(scratchPad, (short) 0, (short) 8);
      repository.setDeviceLock(true);
      repository.setDeviceLockPasswordOnly(tmpVariables[1] == 0x01);
      repository.setDeviceLockTimestamp(scratchPad, (short) 0, (short) 8);
    }
    sendError(apdu, KMError.OK);
  }

  private void resetData() {
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
  public static void sendOutgoing(APDU apdu) {
    if (((short) (bufferProp[BUF_LEN_OFFSET] + bufferProp[BUF_START_OFFSET])) > ((short) repository
        .getHeap().length)) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    apdu.setOutgoing();
    apdu.setOutgoingLength(bufferProp[BUF_LEN_OFFSET]);
    apdu.sendBytesLong((byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
  }

  /**
   * Receives data, which can be extended data, as requested by the command instance.
   */
  public static void receiveIncoming(APDU apdu) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    bufferProp[BUF_LEN_OFFSET] = apdu.getIncomingLength();
    bufferProp[BUF_START_OFFSET] = repository.allocReclaimableMemory(bufferProp[BUF_LEN_OFFSET]);
    short index = bufferProp[BUF_START_OFFSET];

    while (recvLen > 0 && ((short) (index - bufferProp[BUF_START_OFFSET]) < bufferProp[BUF_LEN_OFFSET])) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, (byte[]) bufferRef[0], index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
  }

  private void processGetHwInfoCmd(APDU apdu) {
    // No arguments expected
    final byte[] JavacardKeymasterDevice = {
        0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
        0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
    };
    final byte[] Google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

    // Make the response
    short respPtr = KMArray.instance((short) 3);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 1,
        KMByteBlob.instance(
            JavacardKeymasterDevice, (short) 0, (short) JavacardKeymasterDevice.length));
    resp.add((short) 2, KMByteBlob.instance(Google, (short) 0, (short) Google.length));

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response - actual bufferProp[BUF_LEN_OFFSET] is 86
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(respPtr, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    // send buffer to master
    sendOutgoing(apdu);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Argument 1
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMByteBlob.exp());
    // Decode the argument
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // Process
    KMByteBlob blob = KMByteBlob.cast(KMArray.cast(args).get((short) 0));
    // Maximum 2KiB of seed is allowed.
    if (blob.length() > MAX_SEED_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    seProvider.addRngEntropy(blob.getBuffer(), blob.getStartOff(), blob.length());
    sendError(apdu, KMError.OK);
  }

  private void processSetVersionAndPatchLevels(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    // Argument 1 OS Version
    tmpVariables[0] = KMInteger.exp();
    // Argument 2 OS Patch level
    tmpVariables[1] = KMInteger.exp();
    // Argument 3 Vendor Patch level
    tmpVariables[2] = KMInteger.exp();
    // Array of expected arguments
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, tmpVariables[0]);
    KMArray.cast(argsProto).add((short) 1, tmpVariables[1]);
    KMArray.cast(argsProto).add((short) 2, tmpVariables[2]);
    // Decode the arguments
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[1] = KMArray.cast(args).get((short) 1);
    tmpVariables[2] = KMArray.cast(args).get((short) 2);

    repository.setOsVersion(
      KMInteger.cast(tmpVariables[0]).getBuffer(),
      KMInteger.cast(tmpVariables[0]).getStartOff(),
      KMInteger.cast(tmpVariables[0]).length());

    repository.setOsPatch(
      KMInteger.cast(tmpVariables[1]).getBuffer(),
      KMInteger.cast(tmpVariables[1]).getStartOff(),
      KMInteger.cast(tmpVariables[1]).length());

    repository.setVendorPatchLevel(
      KMInteger.cast(tmpVariables[2]).getBuffer(),
      KMInteger.cast(tmpVariables[2]).getStartOff(),
      KMInteger.cast(tmpVariables[2]).length());

    sendError(apdu, KMError.OK);
  }

  private void processGetCertChainCmd(APDU apdu) {
    // Make the response
    tmpVariables[0] = seProvider.getCertificateChainLength();
    short int32Ptr = buildErrorStatus(KMError.OK);
    //Total Extra length
    // Add arrayHeader and (PowerResetStatus + KMError.OK)
    tmpVariables[2] = (short) (1 + encoder.getEncodedIntegerLength(int32Ptr));
    tmpVariables[0] += tmpVariables[2];
    tmpVariables[1] = KMByteBlob.instance(tmpVariables[0]);
    bufferRef[0] = KMByteBlob.cast(tmpVariables[1]).getBuffer();
    bufferProp[BUF_START_OFFSET] = KMByteBlob.cast(tmpVariables[1]).getStartOff();
    bufferProp[BUF_LEN_OFFSET] = KMByteBlob.cast(tmpVariables[1]).length();
    // read the cert chain from non-volatile memory. Cert chain is already in
    // CBOR format.
    seProvider.readCertificateChain((byte[]) bufferRef[0], (short) (bufferProp[BUF_START_OFFSET] + tmpVariables[2]));
    // Encode cert chain.
    encoder.encodeCertChain((byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET], int32Ptr);
    sendOutgoing(apdu);
  }

  private void processProvisionAttestationCertParams(APDU apdu) {
    receiveIncoming(apdu);
    // Arguments
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 2);
    KMArray.cast(argsProto).add((short) 0, blob); // Cert - DER encoded issuer
    KMArray.cast(argsProto).add((short) 1, blob); // Cert - Expiry Time
    // Decode the argument.
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // save issuer - DER Encoded
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    repository.setIssuer(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());

    // save expiry time - UTC or General Time - YYMMDDhhmmssZ or YYYYMMDDhhmmssZ.
    tmpVariables[0] = KMArray.cast(args).get((short) 1);
    repository.setCertExpiryTime(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());
  }

  private void processProvisionAttestationCertChainCmd(APDU apdu) {
    tmpVariables[0] = seProvider.getCertificateChainLength();
    if (tmpVariables[0] != 0) {
      //Clear the previous certificate chain.
      seProvider.clearCertificateChain();
    }
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    bufferProp[BUF_LEN_OFFSET] = apdu.getIncomingLength();
    bufferProp[BUF_START_OFFSET] = repository.alloc(bufferProp[BUF_LEN_OFFSET]);
    short bytesRead = 0;
    Util.arrayCopyNonAtomic(srcBuffer, srcOffset, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET],
        recvLen);
    // tmpVariables[1] holds the total length + Header length.
    tmpVariables[1] = decoder.readCertificateChainLengthAndHeaderLen((byte[]) bufferRef[0],
        bufferProp[BUF_START_OFFSET], recvLen);
    while (recvLen > 0 && ((short) bytesRead <= bufferProp[BUF_LEN_OFFSET])) {
      seProvider.persistPartialCertificateChain((byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET],
          recvLen, bufferProp[BUF_LEN_OFFSET]);
      bytesRead += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
      if (recvLen > 0) {
        Util.arrayCopyNonAtomic(srcBuffer, srcOffset, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET],
            recvLen);
      }
    }
    if (tmpVariables[1] != bytesRead) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
  }

  private void processProvisionAttestationKey(APDU apdu) {
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormat = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormat);
    KMArray.cast(argsProto).add((short) 2, blob);

    // Decode the argument
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // key params should have os patch, os version and verified root of trust
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMArray.cast(args).get((short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.cast(args).get((short) 2);
    // Key format must be RAW format
    tmpVariables[0] = KMEnum.cast(tmpVariables[0]).getVal();
    if (tmpVariables[0] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    data[ORIGIN] = KMType.IMPORTED;

    // get algorithm - only EC keys expected
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.EC) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // get digest - only SHA256 supported
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short) 0);
      if (tmpVariables[0] != KMType.SHA2_256) {
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      }
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Purpose should be ATTEST_KEY
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short) 0);
      if (tmpVariables[0] != KMType.ATTEST_KEY) {
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Import EC Key - initializes data[SECRET] data[PUB_KEY]
    importECKeys(scratchPad);

    // persist key
    seProvider.createAttestationKey(
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());
  }

  private void processProvisionAttestIdsCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    // Decode the argument.
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    // persist attestation Ids - if any is missing then exception occurs
    saveAttId(KMType.ATTESTATION_ID_BRAND);
    saveAttId(KMType.ATTESTATION_ID_DEVICE);
    saveAttId(KMType.ATTESTATION_ID_PRODUCT);
    saveAttId(KMType.ATTESTATION_ID_MANUFACTURER);
    saveAttId(KMType.ATTESTATION_ID_MODEL);
    saveAttId(KMType.ATTESTATION_ID_IMEI);
    saveAttId(KMType.ATTESTATION_ID_MEID);
    saveAttId(KMType.ATTESTATION_ID_SERIAL);
  }

  private void processProvisionSharedSecretCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Arguments
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, blob);
    // Decode the argument.
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    if (tmpVariables[0] != KMType.INVALID_VALUE
        && KMByteBlob.cast(tmpVariables[0]).length() != KMRepository.SHARED_SECRET_KEY_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Persist shared Hmac.
    seProvider.createPresharedKey(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());
  }

  private void processGetProvisionStatusCmd(APDU apdu) {
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, KMInteger.uint_16(provisionStatus));

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void saveAttId(short attTag) {
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BYTES_TAG, attTag, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
      repository.persistAttId(
          mapToAttId(attTag),
          KMByteBlob.cast(tmpVariables[0]).getBuffer(),
          KMByteBlob.cast(tmpVariables[0]).getStartOff(),
          KMByteBlob.cast(tmpVariables[0]).length());
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  private byte mapToAttId(short attTag) {
    switch (attTag) {
      case KMType.ATTESTATION_ID_BRAND:
        return KMRepository.ATT_ID_BRAND;
      case KMType.ATTESTATION_ID_DEVICE:
        return KMRepository.ATT_ID_DEVICE;
      case KMType.ATTESTATION_ID_IMEI:
        return KMRepository.ATT_ID_IMEI;
      case KMType.ATTESTATION_ID_MANUFACTURER:
        return KMRepository.ATT_ID_MANUFACTURER;
      case KMType.ATTESTATION_ID_MEID:
        return KMRepository.ATT_ID_MEID;
      case KMType.ATTESTATION_ID_MODEL:
        return KMRepository.ATT_ID_MODEL;
      case KMType.ATTESTATION_ID_PRODUCT:
        return KMRepository.ATT_ID_PRODUCT;
      case KMType.ATTESTATION_ID_SERIAL:
        return KMRepository.ATT_ID_SERIAL;
    }
    KMException.throwIt(KMError.INVALID_TAG);
    return (byte) 0xFF; // should never happen
  }

  private void processGetKeyCharacteristicsCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp());
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp());
    KMArray.cast(tmpVariables[0]).add((short) 2, KMByteBlob.exp());
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_BLOB] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[APP_ID] = KMArray.cast(tmpVariables[0]).get((short) 1);
    data[APP_DATA] = KMArray.cast(tmpVariables[0]).get((short) 2);
    if (!KMByteBlob.cast(data[APP_ID]).isValid()) {
      data[APP_ID] = KMType.INVALID_VALUE;
    }
    if (!KMByteBlob.cast(data[APP_DATA]).isValid()) {
      data[APP_DATA] = KMType.INVALID_VALUE;
    }
    // Parse Key Blob
    parseEncryptedKeyBlob(scratchPad);
    // Check Version and Patch Level
    checkVersionAndPatchLevel(scratchPad);
    // make response.
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_CHARACTERISTICS]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void processGetHmacSharingParamCmd(APDU apdu) {
    // No Arguments
    // Create HMAC Sharing Parameters
    tmpVariables[2] = KMHmacSharingParameters.instance();
    KMHmacSharingParameters.cast(tmpVariables[2]).setNonce(repository.getHmacNonce());
    KMHmacSharingParameters.cast(tmpVariables[2]).setSeed(KMByteBlob.instance((short) 0));
    // prepare the response
    tmpVariables[3] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[3]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[3]).add((short) 1, tmpVariables[2]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[3], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void processDeleteAllKeysCmd(APDU apdu) {

    // No arguments
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private void processDeleteKeyCmd(APDU apdu) {

    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Arguments
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMByteBlob.exp());
    // Decode the argument
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // Process
    data[KEY_BLOB] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMByteBlob.cast(data[KEY_BLOB]).getStartOff();
    tmpVariables[1] = KMArray.instance((short) 5);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_SECRET, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_NONCE, KMByteBlob.exp());
    tmpVariables[2] = KMKeyCharacteristics.exp();
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY, KMByteBlob.exp());
    try {
      data[KEY_BLOB] = decoder.decodeArray(tmpVariables[1],
          KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
          KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
          KMByteBlob.cast(data[KEY_BLOB]).length());
    } catch (ISOException e) {
      // As per VTS, deleteKey should return KMError.OK but in case if
      // input is empty then VTS accepts UNIMPLEMENTED errorCode as well.
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    tmpVariables[0] = KMArray.cast(data[KEY_BLOB]).length();
    if (tmpVariables[0] < 4) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Send ok
    sendError(apdu, KMError.OK);
  }

  private void processComputeSharedHmacCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMHmacSharingParameters.exp();
    tmpVariables[0] = KMArray.exp(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[2]).add((short) 0, tmpVariables[0]); // Vector of hmac params
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[2], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[HMAC_SHARING_PARAMS] = KMArray.cast(tmpVariables[0]).get((short) 0);
    // Concatenate HMAC Params
    tmpVariables[0] = KMArray.cast(data[HMAC_SHARING_PARAMS]).length(); // total number of params
    tmpVariables[1] = repository.alloc((short) (tmpVariables[0] * HMAC_SHARED_PARAM_MAX_SIZE));
    tmpVariables[2] = 0; // index for params
    tmpVariables[3] = 0; // index for concatenation buffer
    // To check if nonce created by Strongbox is found. This value becomes 1 if both
    // seed and nonce created here are found in hmac sharing parameters received.
    tmpVariables[7] = 0;
    tmpVariables[9] = repository.getHmacNonce();

    while (tmpVariables[2] < tmpVariables[0]) {
      // read HmacSharingParam
      tmpVariables[4] = KMArray.cast(data[HMAC_SHARING_PARAMS]).get(tmpVariables[2]);
      // get seed - 32 bytes max
      tmpVariables[5] = KMHmacSharingParameters.cast(tmpVariables[4]).getSeed();
      tmpVariables[6] = KMByteBlob.cast(tmpVariables[5]).length();
      // if seed is present
      if (tmpVariables[6] != 0) {
        // then copy that to concatenation buffer
        Util.arrayCopyNonAtomic(
            KMByteBlob.cast(tmpVariables[5]).getBuffer(),
            KMByteBlob.cast(tmpVariables[5]).getStartOff(),
            repository.getHeap(),
            (short) (tmpVariables[1] + tmpVariables[3]), // concat index
            tmpVariables[6]);
        tmpVariables[3] += tmpVariables[6]; // increment the concat index
      } else if (tmpVariables[7] == 0) {
        tmpVariables[7] = 1;
      }
      // if nonce is present get nonce - 32 bytes
      tmpVariables[5] = KMHmacSharingParameters.cast(tmpVariables[4]).getNonce();
      tmpVariables[6] = KMByteBlob.cast(tmpVariables[5]).length();
      // if nonce is not present - it is an error
      if (tmpVariables[6] == 0) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      // copy nonce to concatenation buffer
      Util.arrayCopyNonAtomic(
          KMByteBlob.cast(tmpVariables[5]).getBuffer(),
          KMByteBlob.cast(tmpVariables[5]).getStartOff(),
          repository.getHeap(),
          (short) (tmpVariables[1] + tmpVariables[3]), // index
          tmpVariables[6]);

      // Check if the nonce generated here is present in the hmacSharingParameters array.
      // Otherwise throw INVALID_ARGUMENT error.
      if (tmpVariables[7] == 1) {
        if (0
            == Util.arrayCompare(
            repository.getHeap(),
            (short) (tmpVariables[1] + tmpVariables[3]),
            KMByteBlob.cast(tmpVariables[9]).getBuffer(),
            KMByteBlob.cast(tmpVariables[9]).getStartOff(),
            tmpVariables[6])) {
          tmpVariables[7] = 2; // hmac nonce for this keymaster found.
        } else {
          tmpVariables[7] = 0;
        }
      }
      tmpVariables[3] += tmpVariables[6]; // increment by nonce length
      tmpVariables[2]++; // go to next hmac param in the vector
    }
    if (tmpVariables[7] != 2) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    // generate the key and store it in scratch pad - 32 bytes
    tmpVariables[6] =
        seProvider.cmacKDF(
            seProvider.getPresharedKey(),
            ckdfLable,
            (short) 0,
            (short) ckdfLable.length,
            repository.getHeap(),
            tmpVariables[1],
            tmpVariables[3],
            scratchPad,
            (short) 0);
    // persist the computed hmac key.
    repository.initComputedHmac(scratchPad, (short) 0, tmpVariables[6]);

    // Generate sharingKey verification signature and store that in scratch pad.
    tmpVariables[5] =
        seProvider.hmacSign(
            scratchPad,
            (short) 0,
            tmpVariables[6],
            sharingCheck,
            (short) 0,
            (short) sharingCheck.length,
            scratchPad,
            tmpVariables[6]);
    // verification signature blob - 32 bytes
    tmpVariables[1] = KMByteBlob.instance(scratchPad, tmpVariables[6], tmpVariables[5]);
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private boolean isKeyUpgradeRequired(short tag, short systemParam) {
    // validate the tag and check if key needs upgrade.
    tmpVariables[0] = KMKeyParameters.findTag(KMType.UINT_TAG, tag, data[HW_PARAMETERS]);
    tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();
    tmpVariables[1] = KMInteger.uint_8((byte) 0);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      // OS version in key characteristics must be less the OS version stored in Javacard or the
      // stored version must be zero. Then only upgrade is allowed else it is invalid argument.
      if ((tag == KMType.OS_VERSION
          && KMInteger.compare(tmpVariables[0], systemParam) == 1
          && KMInteger.compare(systemParam, tmpVariables[1]) == 0)) {
        // Key needs upgrade.
        return true;
      } else if ((KMInteger.compare(tmpVariables[0], systemParam) == -1)) {
        // Each os version or patch level associated with the key must be less than it's
        // corresponding value stored in Javacard, then only upgrade is allowed otherwise it
        // is invalid argument.
        return true;
      } else if (KMInteger.compare(tmpVariables[0], systemParam) == 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
    }
    return false;
  }

  private void processUpgradeKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 2);
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMByteBlob.exp()); // Key Blob
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]); // Key Params
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[0]).getValue();
    }
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[0]).getValue();
    }
    // parse existing key blob
    parseEncryptedKeyBlob(scratchPad);
    boolean isKeyUpgradeRequired = false;
    // Check if key requires upgrade.
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.OS_VERSION, repository.getOsVersion());
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.OS_PATCH_LEVEL, repository.getOsPatch());
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.VENDOR_PATCH_LEVEL, repository.getVendorPatchLevel());
    isKeyUpgradeRequired |= isKeyUpgradeRequired(KMType.BOOT_PATCH_LEVEL, repository.getBootPatchLevel());

    if (isKeyUpgradeRequired) {
      // copy origin
      data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
      // create new key blob with current os version etc.
      createEncryptedKeyBlob(scratchPad);
    } else {
      data[KEY_BLOB] = KMByteBlob.instance((short) 0);
    }
    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void processExportKeyCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processImportWrappedKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 12);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[2]); // Key Params of wrapped key
    KMArray.cast(tmpVariables[1]).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT)); // Key Format
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp()); // Wrapped Import Key Blob
    KMArray.cast(tmpVariables[1]).add((short) 3, KMByteBlob.exp()); // Auth Tag
    KMArray.cast(tmpVariables[1]).add((short) 4, KMByteBlob.exp()); // IV - Nonce
    KMArray.cast(tmpVariables[1]).add((short) 5, KMByteBlob.exp()); // Encrypted Transport Key
    KMArray.cast(tmpVariables[1]).add((short) 6, KMByteBlob.exp()); // Wrapping Key KeyBlob
    KMArray.cast(tmpVariables[1]).add((short) 7, KMByteBlob.exp()); // Masking Key
    KMArray.cast(tmpVariables[1]).add((short) 8, tmpVariables[2]); // Un-wrapping Params
    KMArray.cast(tmpVariables[1])
        .add((short) 9, KMByteBlob.exp()); // Wrapped Key ASSOCIATED AUTH DATA
    KMArray.cast(tmpVariables[1]).add((short) 10, KMInteger.exp()); // Password Sid
    KMArray.cast(tmpVariables[1]).add((short) 11, KMInteger.exp()); // Biometric Sid
    // Decode the arguments
    short args = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // Step -0 - check whether the key format and algorithm supported
    // read algorithm
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[1] = KMEnumTag.getValue(KMType.ALGORITHM, tmpVariables[0]);
    // read key format
    tmpVariables[2] = KMArray.cast(args).get((short) 1);
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    // import of RSA and EC not supported with pkcs8 or x509 format
    if ((tmpVariables[1] == KMType.RSA || tmpVariables[1] == KMType.EC)
        && (tmpVariables[2] != KMType.RAW)) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }

    // Step -1 parse the wrapping key blob
    // read wrapping key blob
    data[KEY_BLOB] = KMArray.cast(args).get((short) 6);
    // read un wrapping key params
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 8);
    // Read App Id and App Data if any from un wrapping key params
    data[APP_ID] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    data[APP_DATA] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(tmpVariables[3]).getValue();
    }
    // parse the wrapping key blob
    parseEncryptedKeyBlob(scratchPad);
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
    tmpVariables[0] = KMArray.cast(args).get((short) 5);
    // Decrypt the transport key
    tmpVariables[1] =
        seProvider.rsaDecipherOAEP256(
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
            KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
            KMByteBlob.cast(data[PUB_KEY]).length(),
            KMByteBlob.cast(tmpVariables[0]).getBuffer(),
            KMByteBlob.cast(tmpVariables[0]).getStartOff(),
            KMByteBlob.cast(tmpVariables[0]).length(),
            scratchPad,
            (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[1]);

    // Step 3 - XOR the decrypted AES-GCM key with with masking key
    // read masking key
    tmpVariables[0] = KMArray.cast(args).get((short) 7);
    tmpVariables[1] = KMByteBlob.cast(tmpVariables[0]).length();
    // Length of masking key and transport key must be same.
    if (tmpVariables[1] != KMByteBlob.cast(data[SECRET]).length()) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
    tmpVariables[2] = 0; // index
    // Xor every byte of masking and key and store the result in data[SECRET]
    while (tmpVariables[2] < tmpVariables[1]) {
      tmpVariables[3] =
          (short) (((short) KMByteBlob.cast(tmpVariables[0]).get(tmpVariables[2])) & 0x00FF);
      tmpVariables[4] =
          (short) (((short) KMByteBlob.cast(data[SECRET]).get(tmpVariables[2])) & 0x00FF);
      KMByteBlob.cast(data[SECRET])
          .add(tmpVariables[2], (byte) (tmpVariables[3] ^ tmpVariables[4]));
      tmpVariables[2]++;
    }

    // Step 4 - AES-GCM decrypt the wrapped key
    data[INPUT_DATA] = KMArray.cast(args).get((short) 2);
    data[AUTH_DATA] = KMArray.cast(args).get((short) 9);
    data[AUTH_TAG] = KMArray.cast(args).get((short) 3);
    data[NONCE] = KMArray.cast(args).get((short) 4);
    Util.arrayFillNonAtomic(
        scratchPad, (short) 0, KMByteBlob.cast(data[INPUT_DATA]).length(), (byte) 0);

    if (!seProvider.aesGCMDecrypt(
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
        KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
        KMByteBlob.cast(data[INPUT_DATA]).length(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length(),
        KMByteBlob.cast(data[AUTH_DATA]).getBuffer(),
        KMByteBlob.cast(data[AUTH_DATA]).getStartOff(),
        KMByteBlob.cast(data[AUTH_DATA]).length(),
        KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
        KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
        KMByteBlob.cast(data[AUTH_TAG]).length())) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }

    // Step 5 - Import decrypted key
    data[ORIGIN] = KMType.SECURELY_IMPORTED;
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    // create key blob array
    data[IMPORTED_KEY_BLOB] = KMArray.instance((short) 1);
    // add the byte blob containing decrypted input data
    KMArray.cast(data[IMPORTED_KEY_BLOB])
        .add(
            (short) 0,
            KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(data[INPUT_DATA]).length()));
    // encode the key blob
    tmpVariables[0] = repository.alloc((short) (KMByteBlob.cast(data[INPUT_DATA]).length() + 16));
    tmpVariables[1] =
        encoder.encode(data[IMPORTED_KEY_BLOB], repository.getHeap(), tmpVariables[0]);
    data[IMPORTED_KEY_BLOB] =
        KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
    importKey(apdu, scratchPad);
  }

  private void processAttestKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);

    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();

    // Arguments
    short keyParams = KMKeyParameters.exp();
    short keyBlob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 2);
    KMArray.cast(argsProto).add((short) 0, keyBlob);
    KMArray.cast(argsProto).add((short) 1, keyParams);

    // Decode the argument
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_BLOB] = KMArray.cast(args).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 1);

    // parse key blob
    parseEncryptedKeyBlob(scratchPad);
    // This below code is added to pass one of the VTS 4.1 tests.
    tmpVariables[0] =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.DEVICE_UNIQUE_ATTESTATION, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
    }
    // The key which is being attested should be asymmetric i.e. RSA or EC
    tmpVariables[0] = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.RSA && tmpVariables[0] != KMType.EC) {
      KMException.throwIt(KMError.INCOMPATIBLE_ALGORITHM);
    }
    boolean rsaCert = true;
    if (tmpVariables[0] == KMType.EC) {
      rsaCert = false;
    }
    KMAttestationCert cert = seProvider.getAttestationCert(rsaCert);
    // Save attestation application id - must be present.
    tmpVariables[0] =
        KMKeyParameters.findTag(
            KMType.BYTES_TAG, KMType.ATTESTATION_APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    cert.extensionTag(tmpVariables[0], false);
    // Save attestation challenge
    tmpVariables[0] =
        KMKeyParameters.findTag(
            KMType.BYTES_TAG, KMType.ATTESTATION_CHALLENGE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    cert.attestationChallenge(KMByteTag.cast(tmpVariables[0]).getValue());
    // unique id byte blob - uses application id and temporal month count of creation time.
    setUniqueId(cert, scratchPad);

    // validity period
    // active time or creation time - byte blob
    // current assumption is that if active and creation time are missing from characteristics
    // then
    //  then it is an error.
    tmpVariables[1] =
        KMKeyParameters.findTag(KMType.DATE_TAG, KMType.ACTIVE_DATETIME, data[SW_PARAMETERS]);
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      tmpVariables[1] = KMIntegerTag.cast(tmpVariables[1]).getValue();
    } else {
      tmpVariables[1] =
          KMKeyParameters.findTag(KMType.DATE_TAG, KMType.CREATION_DATETIME, data[SW_PARAMETERS]);
      if (tmpVariables[1] == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      tmpVariables[1] = KMIntegerTag.cast(tmpVariables[1]).getValue();
    }
    // convert milliseconds to UTC date. Start of validity period has to be UTC.
    cert.notBefore(tmpVariables[1], scratchPad);
    // expiry time - byte blob
    tmpVariables[2] =
        KMKeyParameters.findTag(KMType.DATE_TAG, KMType.USAGE_EXPIRE_DATETIME, data[SW_PARAMETERS]);
    cert.notAfter(tmpVariables[2], repository.getCertExpiryTime(), scratchPad, (short) 0);

    addAttestationIds(cert);
    addTags(KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced(), true, cert);
    addTags(
        KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced(), false, cert);

    cert.deviceLocked(repository.getBootLoaderLock());
    cert.issuer(repository.getIssuer());
    cert.publicKey(data[PUB_KEY]);
    cert.verifiedBootHash(repository.getVerifiedBootHash());

    cert.verifiedBootKey(repository.getVerifiedBootKey());
    cert.verifiedBootState(repository.getBootState());
    // buffer for cert - we allocate 2KBytes buffer
    // make this buffer size configurable
    tmpVariables[3] = KMByteBlob.instance(MAX_CERT_SIZE);
    bufferRef[0] = KMByteBlob.cast(tmpVariables[3]).getBuffer();
    bufferProp[BUF_START_OFFSET] = KMByteBlob.cast(tmpVariables[3]).getStartOff();
    bufferProp[BUF_LEN_OFFSET] = KMByteBlob.cast(tmpVariables[3]).length();
    cert.buffer((byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    cert.build();
    bufferProp[BUF_START_OFFSET] =
        encoder.encodeCert((byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], cert.getCertStart(), cert.getCertLength(),
            buildErrorStatus(KMError.OK));
    bufferProp[BUF_LEN_OFFSET] = (short) (cert.getCertLength() + (cert.getCertStart() - bufferProp[BUF_START_OFFSET]));
    sendOutgoing(apdu);
  }

  // --------------------------------
  private void addAttestationIds(KMAttestationCert cert) {
    final short[] attTags =
        new short[]{
            KMType.ATTESTATION_ID_BRAND,
            KMType.ATTESTATION_ID_DEVICE,
            KMType.ATTESTATION_ID_IMEI,
            KMType.ATTESTATION_ID_MANUFACTURER,
            KMType.ATTESTATION_ID_MEID,
            KMType.ATTESTATION_ID_MODEL,
            KMType.ATTESTATION_ID_PRODUCT,
            KMType.ATTESTATION_ID_SERIAL
        };
    byte index = 0;
    short attIdTag;
    while (index < (short) attTags.length) {
      attIdTag = repository.getAttId(mapToAttId(attTags[index]));
      if (attIdTag != 0) {
        attIdTag = KMByteTag.instance(attTags[index], attIdTag);
        cert.extensionTag(attIdTag, true);
      }
      index++;
    }
  }

  private void addTags(short params, boolean hwEnforced, KMAttestationCert cert) {
    short index = 0;
    short arr = KMKeyParameters.cast(params).getVals();
    short len = KMArray.cast(arr).length();
    short tag;
    while (index < len) {
      tag = KMArray.cast(arr).get(index);
      cert.extensionTag(tag, hwEnforced);
      index++;
    }
  }

  private void setUniqueId(KMAttestationCert cert, byte[] scratchPad) {
    tmpVariables[0] = KMKeyParameters.findTag(KMType.BOOL_TAG,
        KMType.INCLUDE_UNIQUE_ID, data[HW_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      return;
    }

    // temporal count T
    tmpVariables[0] = KMKeyParameters.findTag(KMType.DATE_TAG,
        KMType.CREATION_DATETIME, data[SW_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    tmpVariables[0] = KMIntegerTag.cast(tmpVariables[0]).getValue();

    // Application Id C
    tmpVariables[1] = KMKeyParameters.findTag(KMType.BYTES_TAG,
        KMType.ATTESTATION_APPLICATION_ID, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ATTESTATION_APPLICATION_ID_MISSING);
    }
    tmpVariables[1] = KMByteTag.cast(tmpVariables[1]).getValue();

    // Reset After Rotation R - it will be part of HW Enforced key
    // characteristics
    byte resetAfterRotation = 0;
    tmpVariables[2] = KMKeyParameters.findTag(KMType.BOOL_TAG,
        KMType.RESET_SINCE_ID_ROTATION, data[HW_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      resetAfterRotation = 0x01;
    }

    cert.makeUniqueId(
        scratchPad,
        (short) 0,
        KMInteger.cast(tmpVariables[0]).getBuffer(),
        KMInteger.cast(tmpVariables[0]).getStartOff(),
        KMInteger.cast(tmpVariables[0]).length(),
        KMByteBlob.cast(tmpVariables[1]).getBuffer(),
        KMByteBlob.cast(tmpVariables[1]).getStartOff(),
        KMByteBlob.cast(tmpVariables[1]).length(), resetAfterRotation,
        seProvider.getMasterKey());
  }

  private void processDestroyAttIdsCmd(APDU apdu) {
    repository.deleteAttIds();
    sendError(apdu, KMError.OK);
  }

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendError(apdu, KMError.UNIMPLEMENTED);
  }

  private void processAbortOperationCmd(APDU apdu) {
    receiveIncoming(apdu);
    tmpVariables[1] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    KMOperationState op = repository.findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    repository.releaseOperation(op);
    sendError(apdu, KMError.OK);
  }

  private void processFinishOperationCmd(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 6);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add((short) 3, KMByteBlob.exp());
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 4, tmpVariables[3]);
    tmpVariables[4] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 5, tmpVariables[4]);
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[INPUT_DATA] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[SIGNATURE] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[HW_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 4);
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 5);
    // Check Operation Handle
    KMOperationState op = repository.findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // Authorize the finish operation
    authorizeUpdateFinishOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
      case KMType.VERIFY:
        finishSigningVerifyingOperation(op, scratchPad);
        break;
      case KMType.ENCRYPT:
        finishEncryptOperation(op, scratchPad);
        break;
      case KMType.DECRYPT:
        finishDecryptOperation(op, scratchPad);
        break;
    }
    // Remove the operation handle
    repository.releaseOperation(op);
    // make response
    tmpVariables[1] = KMArray.instance((short) 0);
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 3);
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    KMArray.cast(tmpVariables[2]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[2]).add((short) 1, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 2, data[OUTPUT_DATA]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[2], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void finishEncryptOperation(KMOperationState op, byte[] scratchPad) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    switch (op.getAlgorithm()) {
      case KMType.AES:
      case KMType.DES:
        if (op.getAlgorithm() == KMType.AES) {
          tmpVariables[0] = AES_BLOCK_SIZE;
        } else {
          tmpVariables[0] = DES_BLOCK_SIZE;
        }
        // If no padding then data length must be block aligned
        if ((op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC)
            && op.getPadding() == KMType.PADDING_NONE
            && ((short) (len % tmpVariables[0]) != 0)) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        } else if (op.getBlockMode() == KMType.GCM) {
          // update aad if there is any
          updateAAD(op, (byte) 0x01);
          // Get the output size
          len = op.getOperation().getAESGCMOutputSize(len, (short) (op.getMacLength() / 8));
          data[OUTPUT_DATA] = KMByteBlob.instance(len);
        }
        // If padding i.e. pkcs7 then add padding to right
        // Output data can at most one block size more the input data in case of pkcs7 encryption
        tmpVariables[0] = KMByteBlob.instance((short) (len + tmpVariables[0]));
        len =
            op.getOperation()
                .finish(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    KMByteBlob.cast(tmpVariables[0]).getBuffer(),
                    KMByteBlob.cast(tmpVariables[0]).getStartOff());

        data[OUTPUT_DATA] =
            KMByteBlob.instance(
                KMByteBlob.cast(tmpVariables[0]).getBuffer(),
                KMByteBlob.cast(tmpVariables[0]).getStartOff(),
                len);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
  }

  private void finishDecryptOperation(KMOperationState op, byte[] scratchPad) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // Fill the scratch pad with zero
        Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
        if (op.getPadding() == KMType.PADDING_NONE && len != 256) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
        len =
            op.getOperation()
                .finish(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    len,
                    scratchPad,
                    (short) 0);

        data[OUTPUT_DATA] = KMByteBlob.instance(scratchPad, (short) 0, len);
        break;
      case KMType.AES:
      case KMType.DES:
        if (op.getAlgorithm() == KMType.AES) {
          tmpVariables[0] = AES_BLOCK_SIZE;
        } else {
          tmpVariables[0] = DES_BLOCK_SIZE;
        }
        tmpVariables[1] = repository.alloc(len);
        if ((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.ECB)
            && len > 0
            && (len % tmpVariables[0]) != 0) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        } else if (op.getBlockMode() == KMType.GCM) {
          // update aad if there is any
          updateAAD(op, (byte) 0x01);
          // Check if there is at least MAC Length bytes of input data
          if ((len < (short) (op.getMacLength() / 8))) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
          // Get the output size - in case of JCardSim this will more then input size
          tmpVariables[0] =
              op.getOperation().getAESGCMOutputSize(len, (short) (op.getMacLength() / 8));
          tmpVariables[1] = repository.alloc(tmpVariables[0]);
        }
        byte[] heap = repository.getHeap();
        len =
            op.getOperation()
                .finish(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    len,
                    heap,
                    tmpVariables[1]);

        data[OUTPUT_DATA] = KMByteBlob.instance(heap, tmpVariables[1], len);
        break;
    }
  }

  // update operation should send 0x00 for finish variable, where as finish operation
  // should send 0x01 for finish variable.
  private void updateAAD(KMOperationState op, byte finish) {
    // Is input data absent
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Update can be called either to update auth data, update input data or both.
    // But if it is called for neither then return error.
    tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
    tmpVariables[1] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.ASSOCIATED_DATA, data[KEY_PARAMETERS]);
    // For Finish operation the input data can be zero length and associated data can be
    // INVALID_VALUE
    // For update operation either input data or associated data should be present.
    if (tmpVariables[1] == KMType.INVALID_VALUE && tmpVariables[0] <= 0 && finish == 0x00) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    // Check if associated data is present and update aad still allowed by the operation.
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      if (!op.isAesGcmUpdateAllowed()) {
        KMException.throwIt(KMError.INVALID_TAG);
      }
      // If allowed the update the aad
      tmpVariables[1] = KMByteTag.cast(tmpVariables[1]).getValue();

      op.getOperation()
          .updateAAD(
              KMByteBlob.cast(tmpVariables[1]).getBuffer(),
              KMByteBlob.cast(tmpVariables[1]).getStartOff(),
              KMByteBlob.cast(tmpVariables[1]).length());
    }
  }

  private void finishSigningVerifyingOperation(KMOperationState op, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        // If there is no padding we can treat signing as a RSA decryption operation.
        try {
          if (op.getPurpose() == KMType.SIGN) {
            // len of signature will be 256 bytes
            short len = op.getOperation().sign(
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(data[INPUT_DATA]).length(), scratchPad,
                (short) 0);
            // Maximum output size of signature is 256 bytes.
            data[OUTPUT_DATA] = KMByteBlob.instance((short) 256);
            Util.arrayCopyNonAtomic(
                scratchPad,
                (short) 0,
                KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                (short) (KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff() + 256 - len),
                len);
          } else {
            KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
          }
        } catch (CryptoException e) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        break;
      case KMType.EC:
        short len = KMByteBlob.cast(data[INPUT_DATA]).length();
        // If DIGEST NONE then truncate the input data to 32 bytes.
        if (op.getDigest() == KMType.DIGEST_NONE && len > 32) {
          len = 32;
        }
        if (op.getPurpose() == KMType.SIGN) {
          // len of signature will be 512 bits i.e. 64 bytes
          len =
              op.getOperation()
                  .sign(
                      KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                      KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
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
                KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                KMByteBlob.cast(data[INPUT_DATA]).length(),
                scratchPad,
                (short) 0);

        // Copy only signature of mac length size.
        data[OUTPUT_DATA] =
            KMByteBlob.instance(scratchPad, (short) 0, (short) (op.getMacLength() / 8));
        if (op.getPurpose() == KMType.VERIFY) {
          if (0
              != Util.arrayCompare(
              KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[SIGNATURE]).getBuffer(),
              KMByteBlob.cast(data[SIGNATURE]).getStartOff(),
              (short) (op.getMacLength() / 8))) {
            KMException.throwIt(KMError.VERIFICATION_FAILED);
          }
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
      validateVerificationToken(op, data[VERIFICATION_TOKEN], scratchPad);
      tmpVariables[0] = op.getAuthTime();
      tmpVariables[2] = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getTimestamp();
      if (tmpVariables[2] == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
      if (KMInteger.compare(tmpVariables[0], tmpVariables[2]) < 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      op.setAuthTimeoutValidated(true);
    } else if (op.isAuthPerOperationReqd()) { // If Auth per operation is required
      tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getChallenge();
      if (KMInteger.compare(data[OP_HANDLE], tmpVariables[0]) != 0) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      authenticateUser();
    }
  }

  private void authorizeDeviceUnlock(short hwToken) {
    // If device is locked and key characteristics requires unlocked device then check whether
    // HW auth token has correct timestamp.
    short ptr =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED, data[HW_PARAMETERS]);

    if (ptr != KMType.INVALID_VALUE && repository.getDeviceLock()) {
      if (hwToken == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
      // Check if the current auth time stamp is greater then device locked time stamp
      short ts = repository.getDeviceTimeStamp();
      if (KMInteger.compare(ptr, ts) <= 0) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      // Now check if the device unlock requires password only authentication and whether
      // auth token is generated through password authentication or not.
      if (repository.getDeviceLockPasswordOnly()) {
        ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
        ptr = KMEnum.cast(ptr).getVal();
        if (((byte) ptr & KMType.PASSWORD) == 0) {
          KMException.throwIt(KMError.DEVICE_LOCKED);
        }
      }
      // Unlock the device
      // repository.deviceLockedFlag = false;
      repository.setDeviceLock(false);
      repository.clearDeviceLockTimeStamp();
    }
  }

  private void validateVerificationToken(KMOperationState op, short verToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian and Java is big endian
    short ptr = KMVerificationToken.cast(verToken).getMac();
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    validateVerificationToken(verToken, scratchPad);
    // validate operation handle.
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    if (op.getHandle() != KMInteger.cast(ptr).getShort()) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private void validateVerificationToken(short verToken, byte[] scratchPad) {
    short ptr = KMVerificationToken.cast(verToken).getMac();
    short len;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return;
    }
    // concatenation length will be 37 + length of verified parameters list  - which is typically
    // empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopy(
        authVerification, (short) 0, scratchPad, (short) 0, (short) authVerification.length);
    len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate security level - 4 bytes
    ptr = KMVerificationToken.cast(verToken).getSecurityLevel();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate Parameters verified - blob of encoded data.
    ptr = KMVerificationToken.cast(verToken).getParametersVerified();
    if (KMByteBlob.cast(ptr).length() != 0) {
      len += KMByteBlob.cast(ptr).getValues(scratchPad, (short) 0);
    }
    // hmac the data
    ptr = KMVerificationToken.cast(verToken).getMac();
    short key = repository.getComputedHmacKey();
    boolean verified =
        seProvider.hmacVerify(
            KMByteBlob.cast(key).getBuffer(),
            KMByteBlob.cast(key).getStartOff(),
            KMByteBlob.cast(key).length(),
            scratchPad,
            (short) 0,
            len,
            KMByteBlob.cast(ptr).getBuffer(),
            KMByteBlob.cast(ptr).getStartOff(),
            KMByteBlob.cast(ptr).length());

    if (!verified) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
    }
  }

  private void processUpdateOperationCmd(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 5);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMInteger.exp());
    KMArray.cast(tmpVariables[1]).add((short) 1, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 3, tmpVariables[3]);
    tmpVariables[4] = KMVerificationToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 4, tmpVariables[4]);
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[OP_HANDLE] = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[INPUT_DATA] = KMArray.cast(tmpVariables[2]).get((short) 2);
    data[HW_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 3);
    data[VERIFICATION_TOKEN] = KMArray.cast(tmpVariables[2]).get((short) 4);
    // Input data must be present even if it is zero length.
    if (data[INPUT_DATA] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Check Operation Handle and get op state
    // Check Operation Handle
    KMOperationState op = repository.findOperation(data[OP_HANDLE]);
    if (op == null) {
      KMException.throwIt(KMError.INVALID_OPERATION_HANDLE);
    }
    // authorize the update operation
    authorizeUpdateFinishOperation(op, scratchPad);
    // If signing without  digest then do length validation checks
    if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
      tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
      // update the data.
      op.getOperation()
          .update(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());
      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    } else if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
      // Update for encrypt/decrypt using RSA will not be supported because to do this op state
      //  will have to buffer the data - so reject the update if it is rsa algorithm.
      if (op.getAlgorithm() == KMType.RSA) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
      short additionalExpOutLen = 0;
      if (op.getAlgorithm() == KMType.AES) {
        if (op.getBlockMode() == KMType.GCM) {
          updateAAD(op, (byte) 0x00);
          // if input data present
          if (tmpVariables[0] > 0) {
            if (tmpVariables[0] % AES_BLOCK_SIZE != 0) {
              KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
            }
            // no more future updateAAD allowed if input data present.
            if (op.isAesGcmUpdateAllowed()) {
              op.setAesGcmUpdateComplete();
            }
          }
          additionalExpOutLen = 16;
        } else {
          // input data must be block aligned.
          // 128 bit block size - HAL must send block aligned data
          if (tmpVariables[0] % AES_BLOCK_SIZE != 0 || tmpVariables[0] <= 0) {
            KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
          }
        }
      } else if (op.getAlgorithm() == KMType.DES) {
        // 64 bit block size - HAL must send block aligned data
        if (tmpVariables[0] % DES_BLOCK_SIZE != 0) {
          KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
        }
      }
      // Allocate output buffer as input data is already block aligned
      data[OUTPUT_DATA] = KMByteBlob.instance((short) (tmpVariables[0] + additionalExpOutLen));
      // Otherwise just update the data.
      // HAL consumes all the input and maintains a buffered data inside it. So the
      // applet sends the inputConsumed length as same as the input length.
      tmpVariables[3] = tmpVariables[0];
      try {
        tmpVariables[0] =
            op.getOperation()
                .update(
                    KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
                    KMByteBlob.cast(data[INPUT_DATA]).length(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
                    KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
      } catch (CryptoException e) {
        KMException.throwIt(KMError.INVALID_TAG);
      }
      // Adjust the Output data if it is not equal to input data.
      // This happens in case of JCardSim provider.
      if (tmpVariables[0] != KMByteBlob.cast(data[OUTPUT_DATA]).length()) {
        data[INPUT_DATA] = data[OUTPUT_DATA];
        data[OUTPUT_DATA] = KMByteBlob.instance(tmpVariables[0]);
        Util.arrayCopy(
            KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
            KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff(),
            tmpVariables[0]);
      }
    }
    // Persist if there are any updates.
    op.persist();
    // make response
    tmpVariables[1] = KMArray.instance((short) 0);
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[1]);
    tmpVariables[2] = KMArray.instance((short) 4);
    if (data[OUTPUT_DATA] == KMType.INVALID_VALUE) {
      data[OUTPUT_DATA] = KMByteBlob.instance((short) 0);
    }
    KMArray.cast(tmpVariables[2]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[2]).add((short) 1, KMInteger.uint_16(tmpVariables[3]));
    KMArray.cast(tmpVariables[2]).add((short) 2, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 3, data[OUTPUT_DATA]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[2], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    short args;
    tmpVariables[1] = KMArray.instance((short) 4);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, KMEnum.instance(KMType.PURPOSE));
    KMArray.cast(tmpVariables[1]).add((short) 1, KMByteBlob.exp());
    KMArray.cast(tmpVariables[1]).add((short) 2, tmpVariables[2]);
    tmpVariables[3] = KMHardwareAuthToken.exp();
    KMArray.cast(tmpVariables[1]).add((short) 3, tmpVariables[3]);
    // Decode the arguments
    args = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 2);
    data[KEY_BLOB] = KMArray.cast(args).get((short) 1);
    // Check for app id and app data.
    data[APP_ID] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, data[KEY_PARAMETERS]);
    data[APP_DATA] =
        KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, data[KEY_PARAMETERS]);
    if (data[APP_ID] != KMTag.INVALID_VALUE) {
      data[APP_ID] = KMByteTag.cast(data[APP_ID]).getValue();
    }
    if (data[APP_DATA] != KMTag.INVALID_VALUE) {
      data[APP_DATA] = KMByteTag.cast(data[APP_DATA]).getValue();
    }
    // Parse the encrypted blob and decrypt it.
    parseEncryptedKeyBlob(scratchPad);
    // Authorize the begin operation and reserve op - data[OP_HANDLE] will have the handle.
    // It will also set data[IV] field if required.
    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMEnum.cast(tmpVariables[0]).getVal();
    data[HW_TOKEN] = KMArray.cast(args).get((short) 3);
    /*Generate a random number for operation handle */
    short buf = KMByteBlob.instance(KMRepository.OPERATION_HANDLE_SIZE);
    generateUniqueOperationHandle(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    /* opHandle is a KMInteger and is encoded as KMInteger when it is returned back. */
    short opHandle = KMInteger.instance(
        KMByteBlob.cast(buf).getBuffer(),
        KMByteBlob.cast(buf).getStartOff(),
        KMByteBlob.cast(buf).length());
    KMOperationState op = repository.reserveOperation(opHandle);
    if (op == null) {
      KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
    }
    data[OP_HANDLE] = op.getHandle();
    op.setPurpose((byte) tmpVariables[0]);
    op.setKeySize(KMByteBlob.cast(data[SECRET]).length());
    authorizeAndBeginOperation(op, scratchPad);
    switch (op.getPurpose()) {
      case KMType.SIGN:
      case KMType.VERIFY:
        beginSignVerifyOperation(op);
        break;
      case KMType.ENCRYPT:
      case KMType.DECRYPT:
        beginCipherOperation(op);
        break;
      default:
        KMException.throwIt(KMError.UNIMPLEMENTED);
        break;
    }
    // If the data[IV] is required to be returned.
    // As per VTS, for the decryption operation don't send the iv back.
    if (data[IV] != KMType.INVALID_VALUE
        && op.getPurpose() != KMType.DECRYPT
        && op.getBlockMode() != KMType.ECB) {
      tmpVariables[2] = KMArray.instance((short) 1);
      if (op.getAlgorithm() == KMType.DES && op.getBlockMode() == KMType.CBC) {
        // For AES/DES we are generate an random iv of length 16 bytes.
        // While sending the iv back for DES/CBC mode of opeation only send
        // 8 bytes back.
        tmpVariables[1] = KMByteBlob.instance((short) 8);
        Util.arrayCopy(
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(tmpVariables[1]).getBuffer(),
            KMByteBlob.cast(tmpVariables[1]).getStartOff(),
            (short) 8);
        data[IV] = tmpVariables[1];
      }
      KMArray.cast(tmpVariables[2]).add((short) 0, KMByteTag.instance(KMType.NONCE, data[IV]));
    } else {
      tmpVariables[2] = KMArray.instance((short) 0);
    }
    tmpVariables[1] = KMKeyParameters.instance(tmpVariables[2]);
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, tmpVariables[1]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[OP_HANDLE]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void authorizeAlgorithm(KMOperationState op) {
    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[HW_PARAMETERS]);
    if (alg == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    op.setAlgorithm((byte) alg);
  }

  private void authorizePurpose(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.AES:
      case KMType.DES:
        if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
          KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
        }
        break;
      case KMType.EC:
      case KMType.HMAC:
        if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
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
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[HW_PARAMETERS]);
    op.setDigest(KMType.DIGEST_NONE);
    short param =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
      if (!KMEnumArrayTag.cast(digests).contains(param)) {
        KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
      }
      op.setDigest((byte) param);
    }
    short paramPadding =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if (paramPadding != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(paramPadding).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      paramPadding = KMEnumArrayTag.cast(paramPadding).get((short) 0);
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
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
        }
        break;
      default:
        break;
    }
  }

  private void authorizePadding(KMOperationState op) {
    short paddings =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[HW_PARAMETERS]);
    op.setPadding(KMType.PADDING_NONE);
    short param =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PADDING, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
      if (!KMEnumArrayTag.cast(paddings).contains(param)) {
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
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
    if (param != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(param).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      param = KMEnumArrayTag.cast(param).get((short) 0);
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
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
        if (param == KMType.GCM) {
          if (op.getPadding() != KMType.PADDING_NONE) {
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
        if (param == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
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
          } else if (macLen
              > KMIntegerTag.getShortValue(
              KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[HW_PARAMETERS])) {
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
    authorizeAlgorithm(op);
    authorizePurpose(op);
    authorizeDigest(op);
    authorizePadding(op);
    authorizeBlockModeAndMacLength(op);
    if (!validateHwToken(data[HW_TOKEN], scratchPad)) {
      data[HW_TOKEN] = KMType.INVALID_VALUE;
    }
    authorizeUserSecureIdAuthTimeout(op);
    authorizeDeviceUnlock(data[HW_TOKEN]);
    // Authorize Caller Nonce - if caller nonce absent in key char and nonce present in
    // key params then fail if it is not a Decrypt operation
    data[IV] = KMType.INVALID_VALUE;
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.CALLER_NONCE, data[HW_PARAMETERS]);
    tmpVariables[1] = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.NONCE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      if (tmpVariables[1] != KMType.INVALID_VALUE && op.getPurpose() != KMType.DECRYPT) {
        KMException.throwIt(KMError.CALLER_NONCE_PROHIBITED);
      }
    }
    // If Nonce is present then check whether the size of nonce is correct.
    if (tmpVariables[1] != KMType.INVALID_VALUE) {
      data[IV] = KMByteTag.cast(tmpVariables[1]).getValue();
      // For CBC mode - iv must be 8 bytes
      if (op.getBlockMode() == KMType.CBC
          && op.getAlgorithm() == KMType.DES
          && KMByteBlob.cast(data[IV]).length() != 8) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
      // For GCM mode - IV must be 12 bytes
      if (KMByteBlob.cast(data[IV]).length() != 12 && op.getBlockMode() == KMType.GCM) {
        KMException.throwIt(KMError.INVALID_NONCE);
      }
      // For AES CBC and CTR modes IV must be 16 bytes
      if ((op.getBlockMode() == KMType.CBC || op.getBlockMode() == KMType.CTR)
          && op.getAlgorithm() == KMType.AES
          && KMByteBlob.cast(data[IV]).length() != 16) {
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
            KMByteBlob.cast(data[IV]).getBuffer(),
            KMByteBlob.cast(data[IV]).getStartOff(),
            KMByteBlob.cast(data[IV]).length());
      }
    }
  }

  private void beginCipherOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.DECRYPT) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    op.getAlgorithm(),
                    op.getPadding(),
                    op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                    KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                    KMByteBlob.cast(data[PUB_KEY]).length()));
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
                  op.getAlgorithm(),
                  op.getDigest(),
                  op.getPadding(),
                  op.getBlockMode(),
                  KMByteBlob.cast(data[SECRET]).getBuffer(),
                  KMByteBlob.cast(data[SECRET]).getStartOff(),
                  KMByteBlob.cast(data[SECRET]).length(),
                  KMByteBlob.cast(data[IV]).getBuffer(),
                  KMByteBlob.cast(data[IV]).getStartOff(),
                  KMByteBlob.cast(data[IV]).length(),
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

  private void beginSignVerifyOperation(KMOperationState op) {
    switch (op.getAlgorithm()) {
      case KMType.RSA:
        try {
          if (op.getPurpose() == KMType.SIGN) {
            op.setOperation(
                seProvider.initAsymmetricOperation(
                    (byte) op.getPurpose(),
                    op.getAlgorithm(),
                    op.getPadding(),
                    op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
                    KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
                    KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
                    KMByteBlob.cast(data[PUB_KEY]).length()));
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
                    op.getAlgorithm(),
                    op.getPadding(),
                    op.getDigest(),
                    KMByteBlob.cast(data[SECRET]).getBuffer(),
                    KMByteBlob.cast(data[SECRET]).getStartOff(),
                    KMByteBlob.cast(data[SECRET]).length(),
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
                  op.getAlgorithm(),
                  op.getDigest(),
                  op.getPadding(),
                  op.getBlockMode(),
                  KMByteBlob.cast(data[SECRET]).getBuffer(),
                  KMByteBlob.cast(data[SECRET]).getStartOff(),
                  KMByteBlob.cast(data[SECRET]).length(),
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

  private void authorizeUserSecureIdAuthTimeout(KMOperationState op) {
    short authTime;
    // Authorize User Secure Id and Auth timeout
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[0] =
          KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, data[HW_PARAMETERS]);
      if (tmpVariables[0] != KMType.INVALID_VALUE) {
        // check if hw token is empty - mac should not be empty.
        if (data[HW_TOKEN] == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_MAC_LENGTH);
        }
        authTime = KMIntegerTag.cast(tmpVariables[0]).getValue();
        // authenticate user
        authenticateUser();
        // set the one time auth
        op.setOneTimeAuthReqd(true);
        // set the authentication time stamp in operation state
        authTime = addIntegers(authTime, KMHardwareAuthToken.cast(data[HW_TOKEN]).getTimestamp());
        op.setAuthTime(
            KMInteger.cast(authTime).getBuffer(), KMInteger.cast(authTime).getStartOff());
        // auth time validation will happen in update or finish
        op.setAuthTimeoutValidated(false);
      } else {
        // auth per operation required
        op.setOneTimeAuthReqd(false);
        op.setAuthPerOperationReqd(true);
      }
    }
  }

  private void authenticateUser() {
    tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getUserId();
    if (KMInteger.cast(tmpVariables[0]).isZero()) {
      tmpVariables[0] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getAuthenticatorId();
      if (KMInteger.cast(tmpVariables[0]).isZero()) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
    }
    // check user secure id
    if (!KMIntegerArrayTag.contains(KMType.USER_SECURE_ID, tmpVariables[0], data[HW_PARAMETERS])) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
    // check auth type
    tmpVariables[1] = KMEnumTag.getValue(KMType.USER_AUTH_TYPE, data[HW_PARAMETERS]);
    tmpVariables[2] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getHwAuthenticatorType();
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    if (((byte) tmpVariables[2] & (byte) tmpVariables[1]) == 0) {
      KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
    }
  }

  private boolean validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short len;
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return false;
    }
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getUserId();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += 4;
    // concatenate timestamp -8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += 8;
    // hmac the data
    ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    short key = repository.getComputedHmacKey();
    return seProvider.hmacVerify(
        KMByteBlob.cast(key).getBuffer(),
        KMByteBlob.cast(key).getStartOff(),
        KMByteBlob.cast(key).length(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
  }

  private void processImportKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    tmpVariables[1] = KMArray.instance((short) 3);
    // Arguments
    tmpVariables[2] = KMKeyParameters.exp();
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[2]);
    KMArray.cast(tmpVariables[1]).add((short) 1, KMEnum.instance(KMType.KEY_FORMAT));
    KMArray.cast(tmpVariables[1]).add((short) 2, KMByteBlob.exp());
    // Decode the arguments
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    tmpVariables[3] = KMArray.cast(tmpVariables[2]).get((short) 1);
    data[IMPORTED_KEY_BLOB] = KMArray.cast(tmpVariables[2]).get((short) 2);
    // Key format must be RAW format - X509 and PKCS8 not implemented.
    tmpVariables[3] = KMEnum.cast(tmpVariables[3]).getVal();
    if (tmpVariables[3] != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    data[ORIGIN] = KMType.IMPORTED;
    importKey(apdu, scratchPad);
  }

  private void importKey(APDU apdu, byte[] scratchPad) {
    // Bootloader only not supported
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Rollback protection not supported
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    }

    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    //Check if the tags are supported.
    if (KMKeyParameters.hasUnsupportedTags(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_TAG);
    }
    // Check algorithm and dispatch to appropriate handler.
    switch (tmpVariables[3]) {
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
    // create key blob
    createEncryptedKeyBlob(scratchPad);

    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[KEY_CHARACTERISTICS]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void importECKeys(byte[] scratchPad) {
    // Decode key material
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp()); // public key
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[PUB_KEY] = KMArray.cast(tmpVariables[0]).get((short) 1);
    // initialize 256 bit p256 key for given private key and public key.
    tmpVariables[4] = 0; // index for update list in scratchPad

    // check whether the keysize tag is present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret for 256 curve should be between
      // 256-383
      if (((256 <= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))
          && (383 >= (short) (KMByteBlob.cast(data[SECRET]).length() * 8)))
          ^ tmpVariables[2] == 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (tmpVariables[2] != 256) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 256);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // check the curve if present in key parameters.
    tmpVariables[3] = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if (tmpVariables[3] != KMType.INVALID_VALUE) {
      // As per NIST.SP.800-186 page 9,  secret length for 256 curve should be between
      // 256-383
      if (((256 <= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))
          && (383 >= (short) (KMByteBlob.cast(data[SECRET]).length() * 8)))
          ^ tmpVariables[3] == KMType.P_256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      if (tmpVariables[3] != KMType.P_256) {
        KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
      }
    } else {
      // add the curve to scratchPad
      tmpVariables[5] = KMEnumTag.instance(KMType.ECCURVE, KMType.P_256);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[5]);
      tmpVariables[4] += 2;
    }
    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.EC,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length());

    // add scratch pad to key parameters
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate updated key parameters.
    validateECKeys();
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void importHmacKey(byte[] scratchPad) {
    // Get Key
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    // create HMAC key of up to 512 bit

    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (!(tmpVariables[2] >= 64 && tmpVariables[2] <= 512 && tmpVariables[2] % 8 == 0)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) (KMByteBlob.cast(data[SECRET]).length() * 8));
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.HMAC,
        tmpVariables[2],
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate HMAC Key parameters
    validateHmacKey();

    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importTDESKey(byte[] scratchPad) {
    // Decode Key Material
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 168) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 168);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.DES,
        tmpVariables[2],
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate TDES Key parameters
    validateTDESKey();

    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importAESKey(byte[] scratchPad) {
    // Get Key
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    // create 128 or 256 bit AES key
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 128 && tmpVariables[2] != 256) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16(KMByteBlob.cast(data[SECRET]).length());
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }
    // Check whether key can be created
    seProvider.importSymmetricKey(
        KMType.AES,
        tmpVariables[2],
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate AES Key parameters
    validateAESKey();
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void importRSAKey(byte[] scratchPad) {
    // Decode key material
    tmpVariables[0] = KMArray.instance((short) 2);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp()); // secret = private exponent
    KMArray.cast(tmpVariables[0]).add((short) 1, KMByteBlob.exp()); // modulus
    tmpVariables[0] =
        decoder.decode(
            tmpVariables[0],
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getBuffer(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).getStartOff(),
            KMByteBlob.cast(data[IMPORTED_KEY_BLOB]).length());
    data[SECRET] = KMArray.cast(tmpVariables[0]).get((short) 0);
    data[PUB_KEY] = KMArray.cast(tmpVariables[0]).get((short) 1);
    tmpVariables[4] = 0; // index in scratchPad for update parameters.
    // validate public exponent if present in key params - it must be 0x010001
    tmpVariables[2] =
        KMIntegerTag.getValue(
            scratchPad,
            (short) 10, // using offset 10 as first 10 bytes reserved for update params
            KMType.ULONG_TAG,
            KMType.RSA_PUBLIC_EXPONENT,
            data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMTag.INVALID_VALUE) {
      if (tmpVariables[2] != 4
          || Util.getShort(scratchPad, (short) 10) != 0x01
          || Util.getShort(scratchPad, (short) 12) != 0x01) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add public exponent to scratchPad
      Util.setShort(scratchPad, (short) 10, (short) 0x01);
      Util.setShort(scratchPad, (short) 12, (short) 0x01);
      tmpVariables[5] = KMInteger.uint_32(scratchPad, (short) 10);
      tmpVariables[6] =
          KMIntegerTag.instance(KMType.ULONG_TAG, KMType.RSA_PUBLIC_EXPONENT, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }

    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 2048
          || tmpVariables[2] != (short) (KMByteBlob.cast(data[SECRET]).length() * 8)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[5] = KMInteger.uint_16((short) 2048);
      tmpVariables[6] = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, tmpVariables[5]);
      Util.setShort(scratchPad, tmpVariables[4], tmpVariables[6]);
      tmpVariables[4] += 2;
    }

    // Check whether key can be created
    seProvider.importAsymmetricKey(
        KMType.RSA,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length());

    // update the key parameters list
    updateKeyParameters(scratchPad, tmpVariables[4]);
    // validate RSA Key parameters
    validateRSAKey(scratchPad);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void updateKeyParameters(byte[] ptrArr, short len) {
    if (len == 0) {
      return; // nothing to update
    }
    // Create Update Param array and copy current params
    tmpVariables[0] = KMKeyParameters.cast(data[KEY_PARAMETERS]).getVals();
    tmpVariables[1] = (short) (KMArray.cast(tmpVariables[0]).length() + (short) (len / 2));
    tmpVariables[1] = KMArray.instance(tmpVariables[1]); // update params
    tmpVariables[2] = KMArray.cast(tmpVariables[0]).length();
    tmpVariables[3] = 0;
    // copy the existing key parameters to updated array
    while (tmpVariables[3] < tmpVariables[2]) {
      tmpVariables[4] = KMArray.cast(tmpVariables[0]).get(tmpVariables[3]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3], tmpVariables[4]);
      tmpVariables[3]++;
    }
    // copy new parameters to updated array
    tmpVariables[2] = KMArray.cast(tmpVariables[1]).length();
    tmpVariables[5] = 0; // index in ptrArr
    while (tmpVariables[3] < tmpVariables[2]) {
      tmpVariables[4] = Util.getShort(ptrArr, tmpVariables[5]);
      KMArray.cast(tmpVariables[1]).add(tmpVariables[3], tmpVariables[4]);
      tmpVariables[3]++;
      tmpVariables[5] += 2;
    }
    // replace with updated key parameters.
    data[KEY_PARAMETERS] = KMKeyParameters.instance(tmpVariables[1]);
  }

  // This command is executed to set the boot parameters.
  // releaseAllOperations has to be called on every boot, so
  // it is called from inside setBootParams. Later in future if
  // setBootParams is removed, then make sure that releaseAllOperations
  // is moved to a place where it is called on every boot.
  private void processSetBootParamsCmd(APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchPad = apdu.getBuffer();
    // Argument 0 Boot Patch level
    tmpVariables[0] = KMInteger.exp();
    // Argument 1 Verified Boot Key
    tmpVariables[1] = KMByteBlob.exp();
    // Argument 2 Verified Boot Hash
    tmpVariables[2] = KMByteBlob.exp();
    // Argument 3 Verified Boot State
    tmpVariables[3] = KMEnum.instance(KMType.VERIFIED_BOOT_STATE);
    // Argument 4 Device Locked
    tmpVariables[4] = KMEnum.instance(KMType.DEVICE_LOCKED);
    // Array of e4pected arguments
    short argsProto = KMArray.instance((short) 5);
    KMArray.cast(argsProto).add((short) 0, tmpVariables[0]);
    KMArray.cast(argsProto).add((short) 1, tmpVariables[1]);
    KMArray.cast(argsProto).add((short) 2, tmpVariables[2]);
    KMArray.cast(argsProto).add((short) 3, tmpVariables[3]);
    KMArray.cast(argsProto).add((short) 4, tmpVariables[4]);
    // Decode the arguments
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    tmpVariables[0] = KMArray.cast(args).get((short) 0);
    tmpVariables[1] = KMArray.cast(args).get((short) 1);
    tmpVariables[2] = KMArray.cast(args).get((short) 2);
    tmpVariables[3] = KMArray.cast(args).get((short) 3);
    tmpVariables[4] = KMArray.cast(args).get((short) 4);
    if (KMByteBlob.cast(tmpVariables[1]).length() > KMRepository.BOOT_KEY_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (KMByteBlob.cast(tmpVariables[2]).length() > KMRepository.BOOT_HASH_MAX_SIZE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    repository.setBootPatchLevel(
        KMInteger.cast(tmpVariables[0]).getBuffer(),
        KMInteger.cast(tmpVariables[0]).getStartOff(),
        KMInteger.cast(tmpVariables[0]).length());

    repository.setVerifiedBootKey(
        KMByteBlob.cast(tmpVariables[1]).getBuffer(),
        KMByteBlob.cast(tmpVariables[1]).getStartOff(),
        KMByteBlob.cast(tmpVariables[1]).length());

    repository.setVerifiedBootHash(
        KMByteBlob.cast(tmpVariables[2]).getBuffer(),
        KMByteBlob.cast(tmpVariables[2]).getStartOff(),
        KMByteBlob.cast(tmpVariables[2]).length());

    byte enumVal = KMEnum.cast(tmpVariables[3]).getVal();
    repository.setBootState(enumVal);

    enumVal = KMEnum.cast(tmpVariables[4]).getVal();
    repository.setBootloaderLocked(enumVal == KMType.DEVICE_LOCKED_TRUE);

    // Clear Android system properties expect boot patch level as it is
    // already set.
    repository.clearAndroidSystemProperties();

    // Clear the Computed SharedHmac and Hmac nonce from persistent memory.
    repository.clearComputedHmac();
    repository.clearHmacNonce();

    //Clear all the operation state.
    repository.releaseAllOperations();

    // Hmac is cleared, so generate a new Hmac nonce.
    seProvider.newRandomNumber(scratchPad, (short) 0, KMRepository.HMAC_SEED_NONCE_SIZE);
    repository.initHmacNonce(scratchPad, (short) 0, KMRepository.HMAC_SEED_NONCE_SIZE);
  }

  private static void processGenerateKey(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Argument
    tmpVariables[0] = KMKeyParameters.exp();
    // Array of expected arguments
    tmpVariables[1] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[1]).add((short) 0, tmpVariables[0]);
    // Decode the argument
    tmpVariables[2] = decoder.decode(tmpVariables[1], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 0);
    // Check if EarlyBootEnded tag is present.
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.EARLY_BOOT_ENDED);
    }
    // Check if rollback resistance tag is present
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    }
    // Bootloader only not supported
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    tmpVariables[4] =
        KMKeyParameters.findTag(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[4] != KMType.INVALID_VALUE) {
      if (!KMIntegerTag.cast(tmpVariables[4]).isValidKeySize((byte) tmpVariables[3])) {
        KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
    }
    // Only STANDALONE is supported for BLOB_USAGE_REQ tag.
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.BLOB_USAGE_REQ, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[0] = KMEnumTag.getValue(KMType.BLOB_USAGE_REQ, data[KEY_PARAMETERS]);
      if (tmpVariables[0] != KMType.STANDALONE) {
        KMException.throwIt(KMError.UNSUPPORTED_TAG);
      }
    }
    //Check if the tags are supported.
    if (KMKeyParameters.hasUnsupportedTags(data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_TAG);
    }

    // Check algorithm and dispatch to appropriate handler.
    switch (tmpVariables[3]) {
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
    // create key blob
    data[ORIGIN] = KMType.GENERATED;
    createEncryptedKeyBlob(scratchPad);

    // prepare the response
    tmpVariables[0] = KMArray.instance((short) 3);
    KMArray.cast(tmpVariables[0]).add((short) 0, buildErrorStatus(KMError.OK));
    KMArray.cast(tmpVariables[0]).add((short) 1, data[KEY_BLOB]);
    KMArray.cast(tmpVariables[0]).add((short) 2, data[KEY_CHARACTERISTICS]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);

    sendOutgoing(apdu);
  }

  private static void validateRSAKey(byte[] scratchPad) {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    if (tmpVariables[0] != 2048) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read public exponent into scratch pad
    tmpVariables[1] =
        KMIntegerTag.getValue(
            scratchPad,
            (short) 0,
            KMType.ULONG_TAG,
            KMType.RSA_PUBLIC_EXPONENT,
            data[KEY_PARAMETERS]);
    if ((tmpVariables[1] == KMTag.INVALID_VALUE) || (tmpVariables[1] != 4)) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    // Only exponent support is F4 - 65537 which is 0x00010001.
    if (Util.getShort(scratchPad, (short) 0) != 0x01
        || Util.getShort(scratchPad, (short) 2) != 0x01) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
  }

  // Generate key handlers
  private static void generateRSAKey(byte[] scratchPad) {
    // Validate RSA Key
    validateRSAKey(scratchPad);
    // Now generate 2048 bit RSA keypair for the given exponent
    short[] lengths = tmpVariables;
    data[PUB_KEY] = KMByteBlob.instance((short) 256);
    data[SECRET] = KMByteBlob.instance((short) 256);
    seProvider.createAsymmetricKey(
        KMType.RSA,
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        KMByteBlob.cast(data[PUB_KEY]).getBuffer(),
        KMByteBlob.cast(data[PUB_KEY]).getStartOff(),
        KMByteBlob.cast(data[PUB_KEY]).length(),
        lengths);

    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateAESKey() {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if ((tmpVariables[0] != 256) && (tmpVariables[0] != 128)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    // Read Block mode - array of byte values
    tmpVariables[1] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.BLOCK_MODE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] != KMTag.INVALID_VALUE) { // block mode specified
      // Find Minimum Mac length
      tmpVariables[2] =
          KMKeyParameters.findTag(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
      // If block modes contain GCM mode
      if (KMEnumArrayTag.cast(tmpVariables[1]).contains(KMType.GCM)) {
        // minimum mac length must be specified
        if (tmpVariables[2] == KMTag.INVALID_VALUE) {
          KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
        }
        tmpVariables[3] = KMIntegerTag.cast(tmpVariables[2]).getValue();
        // Validate the MIN_MAC_LENGTH for AES - should be multiple of 8, less then 128 bits
        // and greater the 96 bits
        if (KMInteger.cast(tmpVariables[3]).getSignificantShort() != 0
            || KMInteger.cast(tmpVariables[3]).getShort() > 128
            || KMInteger.cast(tmpVariables[3]).getShort() < 96
            || (KMInteger.cast(tmpVariables[3]).getShort() % 8) != 0) {
          KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
        }
      }
    }
  }

  private static void generateAESKey(byte[] scratchPad) {
    validateAESKey();
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    tmpVariables[0] =
        seProvider.createSymmetricKey(KMType.AES, tmpVariables[0], scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateECKeys() {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    tmpVariables[1] = KMEnumTag.getValue(KMType.ECCURVE, data[KEY_PARAMETERS]);
    if ((tmpVariables[0] == KMTag.INVALID_VALUE) && (tmpVariables[1] == KMTag.INVALID_VALUE)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else if ((tmpVariables[0] != KMTag.INVALID_VALUE) && (tmpVariables[0] != (short) 256)) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    } else if ((tmpVariables[1] != KMType.INVALID_VALUE) && (tmpVariables[1] != KMType.P_256)) {
      KMException.throwIt(KMError.UNSUPPORTED_EC_CURVE);
    }
  }

  private static void generateECKeys(byte[] scratchPad) {
    validateECKeys();
    short[] lengths = tmpVariables;
    seProvider.createAsymmetricKey(
        KMType.EC,
        scratchPad,
        (short) 0,
        (short) 128,
        scratchPad,
        (short) 128,
        (short) 128,
        lengths);
    data[PUB_KEY] = KMByteBlob.instance(scratchPad, (short) 128, lengths[1]);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, lengths[0]);
    data[KEY_BLOB] = KMArray.instance((short) 5);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateTDESKey() {
    // Read Minimum Mac length - it must not be present
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (tmpVariables[1] != 168 && tmpVariables[1] != 192) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private static void generateTDESKey(byte[] scratchPad) {
    validateTDESKey();
    tmpVariables[0] = seProvider.createSymmetricKey(KMType.DES, (short) 168, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private static void validateHmacKey() {
    // If params does not contain any digest throw unsupported digest error.
    if (KMType.INVALID_VALUE
        == KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // check whether digest sizes are greater then or equal to min mac length.
    // Only SHA256 digest must be supported.
    if (KMEnumArrayTag.contains(KMType.DIGEST, KMType.DIGEST_NONE, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Read Minimum Mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
    }
    if (((short) (tmpVariables[0] % 8) != 0)
        || (tmpVariables[0] < (short) 64)
        || tmpVariables[0] > (short) 256) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }
    if (((short) (tmpVariables[1] % 8) != 0)
        || (tmpVariables[1] < (short) 64)
        || tmpVariables[1] > (short) 512) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private static void generateHmacKey(byte[] scratchPad) {
    validateHmacKey();
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    // generate HMAC Key
    tmpVariables[0] =
        seProvider.createSymmetricKey(KMType.HMAC, tmpVariables[0], scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = KMArray.instance((short) 4);
  }

  private void checkVersionAndPatchLevel(byte[] scratchPad) {
    tmpVariables[0] =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_VERSION, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[1] = repository.getOsVersion();
      tmpVariables[1] =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.cast(tmpVariables[1]).getBuffer(),
              KMInteger.cast(tmpVariables[1]).getStartOff(),
              scratchPad,
              (short) 0,
              tmpVariables[0]);
      if (tmpVariables[1] == -1) {
        // If the key characteristics has os version > current os version
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (tmpVariables[1] == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
    tmpVariables[0] =
        KMIntegerTag.getValue(
            scratchPad, (short) 0, KMType.UINT_TAG, KMType.OS_PATCH_LEVEL, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      tmpVariables[1] = repository.getOsPatch();
      tmpVariables[1] =
          KMInteger.unsignedByteArrayCompare(
              KMInteger.cast(tmpVariables[1]).getBuffer(),
              KMInteger.cast(tmpVariables[1]).getStartOff(),
              scratchPad,
              (short) 0,
              tmpVariables[0]);
      if (tmpVariables[1] == -1) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      } else if (tmpVariables[1] == 1) {
        KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
      }
    }
  }

  private static void makeKeyCharacteristics(byte[] scratchPad) {
    tmpVariables[0] = repository.getOsPatch();
    tmpVariables[1] = repository.getOsVersion();
    tmpVariables[2] = repository.getVendorPatchLevel();
    tmpVariables[3] = repository.getBootPatchLevel();
    data[HW_PARAMETERS] =
        KMKeyParameters.makeHwEnforced(
            data[KEY_PARAMETERS],
            (byte) data[ORIGIN],
            tmpVariables[1],
            tmpVariables[0],
            tmpVariables[2],
            tmpVariables[3],
            scratchPad);
    data[SW_PARAMETERS] = KMKeyParameters.makeSwEnforced(data[KEY_PARAMETERS], scratchPad);
    data[KEY_CHARACTERISTICS] = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setHardwareEnforced(data[HW_PARAMETERS]);
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setSoftwareEnforced(data[SW_PARAMETERS]);
  }

  private static void createEncryptedKeyBlob(byte[] scratchPad) {
    // make key characteristics - returns key characteristics in data[KEY_CHARACTERISTICS]
    makeKeyCharacteristics(scratchPad);
    // make root of trust blob
    data[ROT] = repository.readROT();
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
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_SECRET, data[SECRET]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_AUTH_TAG, data[AUTH_TAG]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_NONCE, data[NONCE]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_KEYCHAR, data[KEY_CHARACTERISTICS]);

    // allocate reclaimable memory.
    tmpVariables[0] = repository.alloc((short) 1024);
    tmpVariables[1] = encoder.encode(data[KEY_BLOB], repository.getHeap(), tmpVariables[0]);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
  }

  private static void parseEncryptedKeyBlob(byte[] scratchPad) {
    data[ROT] = repository.readROT();
    if (data[ROT] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    try {
      tmpVariables[0] = KMByteBlob.cast(data[KEY_BLOB]).getStartOff();
      tmpVariables[1] = KMArray.instance((short) 5);
      KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_SECRET,
          KMByteBlob.exp());
      KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_AUTH_TAG,
          KMByteBlob.exp());
      KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_NONCE,
          KMByteBlob.exp());
      tmpVariables[2] = KMKeyCharacteristics.exp();
      KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_KEYCHAR,
          tmpVariables[2]);
      KMArray.cast(tmpVariables[1]).add(KMKeymasterApplet.KEY_BLOB_PUB_KEY,
          KMByteBlob.exp());
      data[KEY_BLOB] = decoder.decodeArray(tmpVariables[1],
          KMByteBlob.cast(data[KEY_BLOB]).getBuffer(),
          KMByteBlob.cast(data[KEY_BLOB]).getStartOff(),
          KMByteBlob.cast(data[KEY_BLOB]).length());
      tmpVariables[0] = KMArray.cast(data[KEY_BLOB]).length();
      if (tmpVariables[0] < 4) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      data[AUTH_TAG] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_AUTH_TAG);

      // initialize data
      data[NONCE] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_NONCE);
      data[SECRET] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_SECRET);
      data[KEY_CHARACTERISTICS] = KMArray.cast(data[KEY_BLOB]).get(
          KEY_BLOB_KEYCHAR);
      data[PUB_KEY] = KMType.INVALID_VALUE;
      if (tmpVariables[0] == 5) {
        data[PUB_KEY] = KMArray.cast(data[KEY_BLOB]).get(KEY_BLOB_PUB_KEY);
      }
      data[HW_PARAMETERS] = KMKeyCharacteristics
          .cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced();
      data[SW_PARAMETERS] = KMKeyCharacteristics
          .cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced();

      data[HIDDEN_PARAMETERS] = KMKeyParameters.makeHidden(data[APP_ID],
          data[APP_DATA], data[ROT], scratchPad);
      // make auth data
      makeAuthData(scratchPad);
      // Decrypt Secret and verify auth tag
      decryptSecret(scratchPad);
    } catch (Exception e) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
  }

  private static void decryptSecret(byte[] scratchPad) {
    // derive master key - stored in derivedKey
    tmpVariables[0] = deriveKey(scratchPad);
    if (!seProvider.aesGCMDecrypt(
        repository.getHeap(),
        data[DERIVED_KEY],
        tmpVariables[0],
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length(),
        repository.getHeap(),
        data[AUTH_DATA],
        data[AUTH_DATA_LENGTH],
        KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
        KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
        KMByteBlob.cast(data[AUTH_TAG]).length())) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    // Copy the decrypted secret
    data[SECRET] =
        KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(data[SECRET]).length());
  }

  private static void encryptSecret(byte[] scratchPad) {
    // make nonce
    data[NONCE] = KMByteBlob.instance((short) AES_GCM_NONCE_LENGTH);
    data[AUTH_TAG] = KMByteBlob.instance(AES_GCM_AUTH_TAG_LENGTH);
    Util.arrayCopyNonAtomic(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        scratchPad,
        (short) 0,
        KMByteBlob.cast(data[NONCE]).length());
    seProvider.newRandomNumber(
        KMByteBlob.cast(data[NONCE]).getBuffer(),
        KMByteBlob.cast(data[NONCE]).getStartOff(),
        KMByteBlob.cast(data[NONCE]).length());
    // derive master key - stored in derivedKey
    tmpVariables[0] = deriveKey(scratchPad);
    tmpVariables[1] =
        seProvider.aesGCMEncrypt(
            repository.getHeap(),
            data[DERIVED_KEY],
            tmpVariables[0],
            KMByteBlob.cast(data[SECRET]).getBuffer(),
            KMByteBlob.cast(data[SECRET]).getStartOff(),
            KMByteBlob.cast(data[SECRET]).length(),
            scratchPad,
            (short) 0,
            KMByteBlob.cast(data[NONCE]).getBuffer(),
            KMByteBlob.cast(data[NONCE]).getStartOff(),
            KMByteBlob.cast(data[NONCE]).length(),
            repository.getHeap(),
            data[AUTH_DATA],
            data[AUTH_DATA_LENGTH],
            KMByteBlob.cast(data[AUTH_TAG]).getBuffer(),
            KMByteBlob.cast(data[AUTH_TAG]).getStartOff(),
            KMByteBlob.cast(data[AUTH_TAG]).length());
    if (tmpVariables[1] > 0) {
      if (tmpVariables[1] != KMByteBlob.cast(data[SECRET]).length()) {
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      KMByteBlob.cast(data[SECRET]).setValue(scratchPad, (short) 0, tmpVariables[1]);
    }
  }

  private static void makeAuthData(byte[] scratchPad) {
    tmpVariables[0] =
        addPtrToAAD(KMKeyParameters.cast(data[HW_PARAMETERS]).getVals(), scratchPad, (short) 0);
    tmpVariables[0] +=
        addPtrToAAD(
            KMKeyParameters.cast(data[SW_PARAMETERS]).getVals(), scratchPad, tmpVariables[0]);
    tmpVariables[0] +=
        addPtrToAAD(
            KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals(), scratchPad, tmpVariables[0]);

    if (KMArray.cast(data[KEY_BLOB]).length() == 5) {
      tmpVariables[1] = KMArray.instance((short) (tmpVariables[0] + 1));
    } else {
      tmpVariables[1] = KMArray.instance(tmpVariables[0]);
    }
    // convert scratch pad to KMArray
    short index = 0;
    short objPtr;
    while (index < tmpVariables[0]) {
      objPtr = Util.getShort(scratchPad, (short) (index * 2));
      KMArray.cast(tmpVariables[1]).add(index, objPtr);
      index++;
    }
    if (KMArray.cast(data[KEY_BLOB]).length() == 5) {
      KMArray.cast(tmpVariables[1]).add(index, data[PUB_KEY]);
    }

    data[AUTH_DATA] = repository.alloc(MAX_AUTH_DATA_SIZE);
    short len = encoder.encode(tmpVariables[1], repository.getHeap(), data[AUTH_DATA]);
    data[AUTH_DATA_LENGTH] = len;
  }

  private static short addPtrToAAD(short dataArrPtr, byte[] aadBuf, short offset) {
    short index = (short) (offset * 2);
    short tagInd = 0;
    short tagPtr;
    short arrLen = KMArray.cast(dataArrPtr).length();
    while (tagInd < arrLen) {
      tagPtr = KMArray.cast(dataArrPtr).get(tagInd);
      Util.setShort(aadBuf, index, tagPtr);
      index += 2;
      tagInd++;
    }
    return tagInd;
  }

  private static short deriveKey(byte[] scratchPad) {
    tmpVariables[0] = KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals();
    tmpVariables[1] = repository.alloc(DERIVE_KEY_INPUT_SIZE);
    // generate derivation material from hidden parameters
    tmpVariables[2] = encoder.encode(tmpVariables[0], repository.getHeap(), tmpVariables[1]);
    if (DERIVE_KEY_INPUT_SIZE > tmpVariables[2]) {
      // Copy KeyCharacteristics in the remaining space of DERIVE_KEY_INPUT_SIZE
      Util.arrayCopyNonAtomic(repository.getHeap(), (short) (data[AUTH_DATA]),
          repository.getHeap(),
          (short) (tmpVariables[1] + tmpVariables[2]),
          (short) (DERIVE_KEY_INPUT_SIZE - tmpVariables[2]));
    }
    // KeyDerivation:
    // 1. Do HMAC Sign, with below input parameters.
    //    Key - 128 bit master key
    //    Input data - HIDDEN_PARAMETERS + KeyCharacateristics
    //               - Truncate beyond 256 bytes.
    // 2. HMAC Sign generates an output of 32 bytes length.
    //    Consume only first 16 bytes as derived key.
    // Hmac sign.
    tmpVariables[3] = seProvider.hmacKDF(
        seProvider.getMasterKey(),
        repository.getHeap(),
        tmpVariables[1],
        DERIVE_KEY_INPUT_SIZE,
        scratchPad,
        (short) 0);
    if (tmpVariables[3] < 16) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    tmpVariables[3] = 16;
    // store the derived secret in data dictionary
    data[DERIVED_KEY] = tmpVariables[1];
    Util.arrayCopyNonAtomic(
        scratchPad, (short) 0, repository.getHeap(), data[DERIVED_KEY], tmpVariables[3]);
    return tmpVariables[3];
  }

  // This function masks the error code with POWER_RESET_MASK_FLAG
  // in case if card reset event occurred. The clients of the Applet
  // has to extract the power reset status from the error code and
  // process accordingly.
  private static short buildErrorStatus(short err) {
    short int32Ptr = KMInteger.instance((short) 4);
    short powerResetStatus = 0;
    if (repository.isPowerResetEventOccurred()) {
      powerResetStatus = POWER_RESET_MASK_FLAG;
    }

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        KMInteger.cast(int32Ptr).getStartOff(),
        powerResetStatus);

    Util.setShort(KMInteger.cast(int32Ptr).getBuffer(),
        (short) (KMInteger.cast(int32Ptr).getStartOff() + 2),
        err);

    // reset power reset status flag to its default value.
    repository.restorePowerResetStatus();
    return int32Ptr;
  }

  private static void sendError(APDU apdu, short err) {
    bufferProp[BUF_START_OFFSET] = repository.alloc((short) 5);
    short int32Ptr = buildErrorStatus(err);
    bufferProp[BUF_LEN_OFFSET] = encoder.encodeError(int32Ptr, (byte[]) bufferRef[0],
        bufferProp[BUF_START_OFFSET], (short) 5);
    sendOutgoing(apdu);
  }

  private short addIntegers(short num1, short num2) {
    short buf = repository.alloc((short) 24);
    byte[] scratchPad = repository.getHeap();
    Util.arrayFillNonAtomic(scratchPad, buf, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.cast(num1).getBuffer(),
        KMInteger.cast(num1).getStartOff(),
        scratchPad,
        (short) (buf + 8 - KMInteger.cast(num1).length()),
        KMInteger.cast(num1).length());
    Util.arrayCopyNonAtomic(
        KMInteger.cast(num2).getBuffer(),
        KMInteger.cast(num2).getStartOff(),
        scratchPad,
        (short) (buf + 16 - KMInteger.cast(num2).length()),
        KMInteger.cast(num2).length());
    add(scratchPad, buf, (short) (buf + 8), (short) (buf + 16));
    return KMInteger.uint_64(scratchPad, (short) (buf + 16));
  }

  private void add(byte[] buf, short op1, short op2, short result) {
    byte index = 7;
    byte carry = 0;
    short tmp;
    while (index >= 0) {
      tmp = (short) (buf[(short) (op1 + index)] + buf[(short) (op2 + index)] + carry);
      carry = 0;
      if (tmp > 255) {
        carry = 1; // max unsigned byte value is 255
      }
      buf[(short) (result + index)] = (byte) (tmp & (byte) 0xFF);
      index--;
    }
  }
}
