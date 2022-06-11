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
  public static final byte[] F4 = {0x01, 0x00, 0x01};	
  public static final byte AES_BLOCK_SIZE = 16;
  public static final byte DES_BLOCK_SIZE = 8;
  public static final short MAX_LENGTH = (short) 0x2000;
  private static final short KM_HAL_VERSION = (short) 0x4000;
  private static final short MAX_AUTH_DATA_SIZE = (short) 512;
  private static final short POWER_RESET_MASK_FLAG = (short) 0x4000;
  // Magic number version
  public static final byte KM_MAGIC_NUMBER = (byte) 0x81;
  // MSB byte is for Major version and LSB byte is for Minor version.
  // Whenever there is an applet upgrade change the version.
  public static final short KM_APPLET_PACKAGE_VERSION = 0x0300; // 3.0

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
  
  // getHardwareInfo constants.
  private static final byte[] JAVACARD_KEYMASTER_DEVICE = {
      0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74,
      0x65, 0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
  };
  private static final byte[] GOOGLE = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

  // OEM lock / unlock verification constants.
  private static final byte[] OEM_LOCK_VERIFICATION_LABEL = { // "OEM Provisioning Lock"
      0x4f, 0x45, 0x4d, 0x20, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e,
      0x67, 0x20, 0x4c, 0x6f, 0x63, 0x6b
  };
  private static final byte[] OEM_UNLOCK_VERIFICATION_LABEL = { // "Enable RMA"
      0x45, 0x6e, 0x61, 0x62, 0x6c, 0x65, 0x20, 0x52, 0x4d, 0x41
  };
  // Attestation IDs
  private static final short[] ATTEST_ID_TAGS = {
          KMType.ATTESTATION_ID_BRAND,
          KMType.ATTESTATION_ID_DEVICE,
          KMType.ATTESTATION_ID_IMEI,
          KMType.ATTESTATION_ID_MANUFACTURER,
          KMType.ATTESTATION_ID_MEID,
          KMType.ATTESTATION_ID_MODEL,
          KMType.ATTESTATION_ID_PRODUCT,
          KMType.ATTESTATION_ID_SERIAL
      };

  // Commands
  private static final byte INS_BEGIN_KM_CMD = 0x00;
  // Instructions for Provision Commands.
  private static final byte INS_PROVISION_ATTESTATION_KEY_CMD = INS_BEGIN_KM_CMD + 1; //0x01
  private static final byte INS_PROVISION_ATTESTATION_CERT_DATA_CMD = INS_BEGIN_KM_CMD + 2; //0x02
  private static final byte INS_PROVISION_ATTEST_IDS_CMD = INS_BEGIN_KM_CMD + 3; //0x03
  private static final byte INS_PROVISION_PRESHARED_SECRET_CMD = INS_BEGIN_KM_CMD + 4; //0x04
  private static final byte INS_SET_BOOT_PARAMS_CMD = INS_BEGIN_KM_CMD + 5; //0x05
  private static final byte INS_OEM_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 6; //0x06
  private static final byte INS_GET_PROVISION_STATUS_CMD = INS_BEGIN_KM_CMD + 7; //0x07
  private static final byte INS_SET_VERSION_PATCHLEVEL_CMD = INS_BEGIN_KM_CMD + 8; //0x08
  private static final byte INS_SET_BOOT_ENDED_CMD = INS_BEGIN_KM_CMD + 9; //0x09 // Unused
  private static final byte INS_SE_FACTORY_LOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 10; //0x0A
  private static final byte INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD = INS_BEGIN_KM_CMD + 11; //0x0B
  private static final byte INS_OEM_UNLOCK_PROVISIONING_CMD = INS_BEGIN_KM_CMD + 12; //0x0C

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
  protected static final byte NOT_PROVISIONED = 0x00;
  protected static final byte PROVISION_STATUS_ATTESTATION_KEY = 0x01;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_CHAIN = 0x02;
  private static final byte PROVISION_STATUS_ATTESTATION_CERT_PARAMS = 0x04;
  protected static final byte PROVISION_STATUS_ATTEST_IDS = 0x08;
  protected static final byte PROVISION_STATUS_PRESHARED_SECRET = 0x10;
  protected static final byte PROVISION_STATUS_OEM_PROVISIONING_LOCKED = 0x20;
  protected static final byte PROVISION_STATUS_SE_FACTORY_PROVISIONING_LOCKED = 0x40;
  protected static final byte PROVISION_STATUS_OEM_ROOT_PUBLIC_KEY = (byte) 0x80;

  // Data Dictionary items
  public static final byte DATA_ARRAY_SIZE = 31;
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
  public static final byte KEY_BLOB_VERSION_DATA_OFFSET = 29;
  public static final byte CUSTOM_TAGS = 30;
  

  // AddRngEntropy
  protected static final short MAX_SEED_SIZE = 2048;
  // Keyblob constants
  public static final byte KEY_BLOB_VERSION_OFFSET = 0;
  public static final byte KEY_BLOB_SECRET = 1;
  public static final byte KEY_BLOB_NONCE = 2;
  public static final byte KEY_BLOB_AUTH_TAG = 3;
  public static final byte KEY_BLOB_KEYCHAR = 4;
  public static final byte KEY_BLOB_CUSTOM_TAGS = 5;
  public static final byte KEY_BLOB_PUB_KEY = 6;
 
  //KeyBlob array size constants.
  public static final byte SYM_KEY_BLOB_SIZE_V1 = 6;
  public static final byte ASYM_KEY_BLOB_SIZE_V1 = 7;
  public static final byte SYM_KEY_BLOB_SIZE_V0 = 4;
  public static final byte ASYM_KEY_BLOB_SIZE_V0 = 5;
 // Key type constants
  public static final byte SYM_KEY_TYPE = 0;
  public static final byte ASYM_KEY_TYPE = 1;
 
  // AES GCM constants
  private static final byte AES_GCM_AUTH_TAG_LENGTH = 16;
  private static final byte AES_GCM_NONCE_LENGTH = 12;
  // ComputeHMAC constants
  private static final short HMAC_SHARED_PARAM_MAX_SIZE = 64;
  // Maximum certificate size.
  private static final short MAX_CERT_SIZE = 3000;
  // Buffer constants.
  private static final short BUF_START_OFFSET = 0;
  private static final short BUF_LEN_OFFSET = 2;
  
  //KEYBLOB_CURRENT_VERSION goes into KeyBlob and will affect all
  // the KeyBlobs if it is changed. please increment this
  // version number whenever you change anything related to
  // KeyBlob (structure, encryption algorithm etc).
  public static final short KEYBLOB_CURRENT_VERSION = 1;
  // KeyBlob Verion 1 constant.
  public static final short KEYBLOB_VERSION_0 = 0;
  // Device boot states. Applet starts executing the
  // core commands once all the states are set. The commands
  // that are allowed irrespective of these states are:
  // All the provision commands
  // INS_GET_HW_INFO_CMD
  // INS_ADD_RNG_ENTROPY_CMD
  // INS_COMPUTE_SHARED_HMAC_CMD
  // INS_GET_HMAC_SHARING_PARAM_CMD
  public static final byte SET_BOOT_PARAMS_SUCCESS = 0x01;
  public static final byte SET_SYSTEM_PROPERTIES_SUCCESS = 0x02;
  public static final byte NEGOTIATED_SHARED_SECRET_SUCCESS = 0x04;

  // Keymaster Applet attributes
  protected static byte keymasterState;
  protected static KMEncoder encoder;
  protected static KMDecoder decoder;
  protected static KMRepository repository;
  protected static KMSEProvider seProvider;
  protected static Object[] bufferRef;
  protected static short[] bufferProp;
  protected static short[] tmpVariables;
  protected static short[] data;
  protected static byte provisionStatus = NOT_PROVISIONED;
  // First two bytes are Major version and second bytes are minor version.
  protected short packageVersion;
  

  /**
   * Registers this applet.
   */
  protected KMKeymasterApplet(KMSEProvider seImpl) {
    seProvider = seImpl;
    boolean isUpgrading = seImpl.isUpgrading();
    repository = new KMRepository(isUpgrading);
    initializeTransientArrays();
    if (!isUpgrading) {
      keymasterState = KMAppletState.INIT_STATE;
      seProvider.createMasterKey((short) (KMRepository.MASTER_KEY_SIZE * 8));
    }
    packageVersion = KM_APPLET_PACKAGE_VERSION;
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
    if (keymasterState == KMAppletState.INIT_STATE) {
      keymasterState = KMAppletState.IN_PROVISION_STATE;
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
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);

    // Validate CLA 
    if (!seProvider.isValidCLA(apdu)) {
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
      resetTransientBuffers();
      // Handle the card reset status before processing apdu.
      if (repository.isPowerResetEventOccurred()) {
        // Release all the operation instances.
        seProvider.releaseAllOperations();
      }
      repository.onProcess();
      // Verify whether applet is in correct state.
      if (keymasterState == KMAppletState.INIT_STATE) {
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
      // Below instructions are allowed in both active state and provision state.
      switch (apduIns) {
      case INS_SET_BOOT_PARAMS_CMD:
        // Allow set boot params only when the host device reboots and the applet is in
        // active state. If host does not support boot signal event, then allow this
        // instruction any time.
        if (seProvider.isBootSignalEventSupported()
            && (keymasterState == KMAppletState.ACTIVE_STATE)
            && (!seProvider.isDeviceRebooted())) {
          ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
        // clear the device reboot status
        repository.setDeviceBootStatus((byte) 0x00);
        processSetBootParamsCmd(apdu);
        //set the flag to mark boot started
        repository.setDeviceBootStatus(SET_BOOT_PARAMS_SUCCESS);
        seProvider.clearDeviceBooted(false);

        sendResponse(apdu, KMError.OK);
        return;

      case INS_GET_PROVISION_STATUS_CMD:
        processGetProvisionStatusCmd(apdu);
        return;

      default:
        // Fallback to instructions specific to either provision state or active state
        // or both.
        break;
      }
      
      // Below instructions are allowed in only provision state.
      if (keymasterState == KMAppletState.IN_PROVISION_STATE) {
        switch (apduIns) {
          case INS_PROVISION_ATTESTATION_KEY_CMD:
            if (!isSEFactoryProvisioningLocked()) {
              processProvisionAttestationKey(apdu);
              provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_KEY;
              sendResponse(apdu, KMError.OK);
            } else {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            return;

          case INS_PROVISION_ATTESTATION_CERT_DATA_CMD:
            if (!isSEFactoryProvisioningLocked()) {
              processProvisionAttestationCertDataCmd(apdu);
              provisionStatus |= (KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_CERT_CHAIN |
                  KMKeymasterApplet.PROVISION_STATUS_ATTESTATION_CERT_PARAMS);
              sendResponse(apdu, KMError.OK);
            } else {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            return;

          case INS_SE_FACTORY_LOCK_PROVISIONING_CMD:
            if (isSEFactoryProvisioningComplete()) {
              provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_SE_FACTORY_PROVISIONING_LOCKED;
              sendResponse(apdu, KMError.OK);
            } else {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            return;

          case INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD:
            processProvisionOEMRootPublicKeyCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_OEM_ROOT_PUBLIC_KEY;
            sendResponse(apdu, KMError.OK);
            return;

          case INS_PROVISION_ATTEST_IDS_CMD:
            processProvisionAttestIdsCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_ATTEST_IDS;
            sendResponse(apdu, KMError.OK);
            return;

          case INS_PROVISION_PRESHARED_SECRET_CMD:
            processProvisionSharedSecretCmd(apdu);
            provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_PRESHARED_SECRET;
            sendResponse(apdu, KMError.OK);
            return;

          case INS_OEM_LOCK_PROVISIONING_CMD:
            // Allow lock only when
            // 1. All the necessary provisioning commands are successfully executed
            // 2. SE provision is locked
            // 3. OEM Root Public is provisioned.
            if (isProvisioningComplete() &&
                (0 != (provisionStatus & PROVISION_STATUS_OEM_ROOT_PUBLIC_KEY)) &&
                (0 != (provisionStatus & PROVISION_STATUS_SE_FACTORY_PROVISIONING_LOCKED)) ) {
              processOEMLockProvisionCmd(apdu);
            } else {
              ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
            return;

          case INS_OEM_UNLOCK_PROVISIONING_CMD:
            // UNLOCK command not allowed in IN_PROVISION_STATE
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            return;

          default:
            // Fallback to instructions specific to either active state or
            // provision completed but not locked state.
            break;
        }
      }

      // Below instructions are allowed only in active state and provision completed state.
      if ((keymasterState == KMAppletState.ACTIVE_STATE)
          || ((keymasterState == KMAppletState.IN_PROVISION_STATE)
          && isProvisioningComplete())) {

        if (!isKeymasterReady(apduIns)) {
          KMException.throwIt(KMError.UNKNOWN_ERROR);
        }
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
          case INS_OEM_UNLOCK_PROVISIONING_CMD:
            processOEMUnlockProvisionCmd(apdu);
            break;
          case INS_PROVISION_ATTEST_IDS_CMD:
          case INS_PROVISION_ATTESTATION_KEY_CMD:
          case INS_PROVISION_ATTESTATION_CERT_DATA_CMD:
          case INS_PROVISION_OEM_ROOT_PUBLIC_KEY_CMD:
          case INS_PROVISION_PRESHARED_SECRET_CMD:
          case INS_SE_FACTORY_LOCK_PROVISIONING_CMD:
          case INS_OEM_LOCK_PROVISIONING_CMD:
            // Provision commands are not allowed in ACTIVE_STATE
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            break;
          default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
      } else {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
    } catch (KMException exception) {
      freeOperations();
      sendResponse(apdu, KMException.getReason());
      exception.clear();
    } catch (ISOException exp) {
      freeOperations();
      sendResponse(apdu, mapISOErrorToKMError(exp.getReason()));
    } catch (CryptoException e) {
      freeOperations();
      sendResponse(apdu, mapCryptoErrorToKMError(e.getReason()));
    } catch (Exception e) {
      freeOperations();
      sendResponse(apdu, KMError.GENERIC_UNKNOWN_ERROR);
    } finally {
      repository.clean();
    }
  }

  // After every device boot, the Keymaster becomes ready to execute all the commands only after
  // 1. boot parameters are set,
  // 2. system properties are set and
  // 3. computed the shared secret successfully.
  private boolean isKeymasterReady(byte apduIns) {
      byte deviceBootStatus =
          (SET_BOOT_PARAMS_SUCCESS | SET_SYSTEM_PROPERTIES_SUCCESS |
              NEGOTIATED_SHARED_SECRET_SUCCESS);
      if (repository.getDeviceBootStatus() == deviceBootStatus) {
        // Keymaster is ready to execute all the commands.
        return true;
      }
      // Below commands are allowed even if the Keymaster is not ready.
      switch (apduIns) {
        case INS_GET_HW_INFO_CMD:
        case INS_ADD_RNG_ENTROPY_CMD:
        case INS_GET_HMAC_SHARING_PARAM_CMD:
        case INS_COMPUTE_SHARED_HMAC_CMD:
        case INS_SET_VERSION_PATCHLEVEL_CMD:
        case INS_OEM_UNLOCK_PROVISIONING_CMD:
          return true;
        default:
          break;
      }
      return false;
  }

  private void setDeviceBootStatus(byte deviceRebootStatus) {
    byte status = repository.getDeviceBootStatus();
    status |= deviceRebootStatus;
    repository.setDeviceBootStatus(status);
  }

  private void generateUniqueOperationHandle(byte[] buf, short offset, short len) {
    do {
      seProvider.newRandomNumber(buf, offset, len);
    } while (null != repository.findOperation(buf, offset, len));
  }

  private boolean isSEFactoryProvisioningLocked() {
    return (0 != (provisionStatus & PROVISION_STATUS_SE_FACTORY_PROVISIONING_LOCKED));
  }

  private boolean isSEFactoryProvisioningComplete() {
    if ((0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_KEY))
        && (0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_CERT_CHAIN))
        && (0 != (provisionStatus & PROVISION_STATUS_ATTESTATION_CERT_PARAMS))) {
      return true;
    } else {
      return false;
    }
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

  private void processOEMUnlockProvisionCmd(APDU apdu) {
    authenticateOEM(OEM_UNLOCK_VERIFICATION_LABEL, apdu);
    // Set the OEM Lock bit LOW in provisionStatus.
    provisionStatus &= ~KMKeymasterApplet.PROVISION_STATUS_OEM_PROVISIONING_LOCKED;
    keymasterState = KMAppletState.IN_PROVISION_STATE;
    sendResponse(apdu, KMError.OK);
  }

  private void processOEMLockProvisionCmd(APDU apdu) {
    authenticateOEM(OEM_LOCK_VERIFICATION_LABEL, apdu);
    // Set the OEM Lock bit HIGH in provisionStatus.
    provisionStatus |= KMKeymasterApplet.PROVISION_STATUS_OEM_PROVISIONING_LOCKED;
    keymasterState = KMAppletState.ACTIVE_STATE;
    sendResponse(apdu, KMError.OK);
  }

  private void authenticateOEM(byte[] plainMsg, APDU apdu) {
    receiveIncoming(apdu);
    byte[] scratchpad = apdu.getBuffer();
    tmpVariables[0] = KMArray.instance((short) 1);
    KMArray.cast(tmpVariables[0]).add((short) 0, KMByteBlob.exp());
    // Decode the arguments
    tmpVariables[0] = decoder.decode(tmpVariables[0], (byte[]) bufferRef[0],
        bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);
    // Get the signature input.
    short signature = KMArray.cast(tmpVariables[0]).get((short) 0);
    short ecPubKeyLen = seProvider.readOEMRootPublicKey(scratchpad, (short) 0);

    if (!seProvider.ecVerify256(
        scratchpad, (short) 0, (short) ecPubKeyLen,
        plainMsg, (short) 0, (short) plainMsg.length,
        KMByteBlob.cast(signature).getBuffer(),
        KMByteBlob.cast(signature).getStartOff(),
        KMByteBlob.cast(signature).length())) {
      KMException.throwIt(KMError.VERIFICATION_FAILED);
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
    repository.setEarlyBootEndedStatus(true);
    sendResponse(apdu, KMError.OK);
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
    short lastDeviceLockedTime;
    try {
      lastDeviceLockedTime = repository.getDeviceTimeStamp();
    } catch (KMException e) {
      lastDeviceLockedTime = KMInteger.uint_8((byte) 0);
    }
    if (KMInteger.compare(verTime, lastDeviceLockedTime) > 0) {
      Util.arrayFillNonAtomic(scratchPad, (short) 0, KMInteger.UINT_64, (byte) 0);
      KMInteger.cast(verTime).getValue(scratchPad, (short) 0, KMInteger.UINT_64);
      repository.setDeviceLock(true);
      repository.setDeviceLockPasswordOnly(tmpVariables[1] == 0x01);
      repository.setDeviceLockTimestamp(scratchPad, (short) 0, KMInteger.UINT_64);
    }
    sendResponse(apdu, KMError.OK);
  }

  private void resetTransientBuffers() {
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
    // Make the response
    short respPtr = KMArray.instance((short) 3);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add(
        (short) 1,
        KMByteBlob.instance(
            JAVACARD_KEYMASTER_DEVICE, (short) 0, (short) JAVACARD_KEYMASTER_DEVICE.length));
    resp.add((short) 2, KMByteBlob.instance(GOOGLE, (short) 0, (short) GOOGLE.length));

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response - actual bufferProp[BUF_LEN_OFFSET] is 86
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(respPtr, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    // send buffer to host
    sendOutgoing(apdu);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the host.
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
    sendResponse(apdu, KMError.OK);
  }

  private void processSetVersionAndPatchLevels(APDU apdu) {
    receiveIncoming(apdu);
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

    setDeviceBootStatus(SET_SYSTEM_PROPERTIES_SUCCESS);
    sendResponse(apdu, KMError.OK);
  }
  
  private short getProvisionedCertificateData(byte dataType) {
    short len = seProvider.getProvisionedDataLength(dataType);
    if (len == 0) {
      KMException.throwIt(KMError.INVALID_DATA);
    }
    short ptr = KMByteBlob.instance(len);
    seProvider.readProvisionedData(
        dataType,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff());
    return ptr;
  }

  private void processGetCertChainCmd(APDU apdu) {
    // Make the response
    short certChainLen = seProvider.getProvisionedDataLength(KMSEProvider.CERTIFICATE_CHAIN);
    short int32Ptr = buildErrorStatus(KMError.OK);
    short maxByteHeaderLen = 3; // Maximum possible ByteBlob header len.
    short arrayHeaderLen = 1;
    // Allocate maximum possible buffer.
    // Add arrayHeader + (PowerResetStatus + KMError.OK) + Byte Header
    short totalLen = (short) (arrayHeaderLen + encoder.getEncodedIntegerLength(int32Ptr) + maxByteHeaderLen + certChainLen);
    tmpVariables[1] = KMByteBlob.instance(totalLen);
    bufferRef[0] = KMByteBlob.cast(tmpVariables[1]).getBuffer();
    bufferProp[BUF_START_OFFSET] = KMByteBlob.cast(tmpVariables[1]).getStartOff();
    bufferProp[BUF_LEN_OFFSET] = KMByteBlob.cast(tmpVariables[1]).length();
    // copy the certificate chain to the end of the buffer.
    seProvider.readProvisionedData(
        KMSEProvider.CERTIFICATE_CHAIN,
        (byte[]) bufferRef[0],
        (short) (bufferProp[BUF_START_OFFSET] + totalLen - certChainLen));
    // Encode cert chain.
    encoder.encodeCertChain((byte[]) bufferRef[0],
        bufferProp[BUF_START_OFFSET],
        bufferProp[BUF_LEN_OFFSET],
        int32Ptr, // uint32 ptr
        (short) (bufferProp[BUF_START_OFFSET] + totalLen - certChainLen), // start pos of cert chain.
        certChainLen);
    sendOutgoing(apdu);
  }

  private void processProvisionAttestationCertDataCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Buffer holds the corresponding offsets and lengths of the certChain, certIssuer and certExpiry
    // in the bufferRef[0] buffer.
    short var = KMByteBlob.instance((short) 12);
    // These variables point to the appropriate positions in the var buffer.
    short certChainPos = KMByteBlob.cast(var).getStartOff();
    short certIssuerPos = (short) (KMByteBlob.cast(var).getStartOff() + 4);
    short certExpiryPos = (short) (KMByteBlob.cast(var).getStartOff() + 8);
    decoder.decodeCertificateData((short) 3,
        (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET], bufferProp[BUF_LEN_OFFSET],
        KMByteBlob.cast(var).getBuffer(), KMByteBlob.cast(var).getStartOff());
    // persist data
    seProvider.persistProvisionData(
        (byte[]) bufferRef[0],
        Util.getShort(KMByteBlob.cast(var).getBuffer(), certChainPos), // offset
        Util.getShort(KMByteBlob.cast(var).getBuffer(), (short) (certChainPos + 2)), // length
        Util.getShort(KMByteBlob.cast(var).getBuffer(), certIssuerPos), // offset
        Util.getShort(KMByteBlob.cast(var).getBuffer(), (short) (certIssuerPos + 2)), // length
        Util.getShort(KMByteBlob.cast(var).getBuffer(), certExpiryPos), // offset
        Util.getShort(KMByteBlob.cast(var).getBuffer(), (short) (certExpiryPos + 2))); // length
        
    // reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);
  }

  private void processProvisionAttestationKey(APDU apdu) {
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormatPtr);
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
    byte keyFormat = KMEnum.cast(tmpVariables[0]).getVal();
    if (keyFormat != KMType.RAW) {
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
    importECKeys(scratchPad, keyFormat);

    // persist key
    seProvider.createAttestationKey(
        KMByteBlob.cast(data[SECRET]).getBuffer(),
        KMByteBlob.cast(data[SECRET]).getStartOff(),
        KMByteBlob.cast(data[SECRET]).length());
  }

  private void processProvisionOEMRootPublicKeyCmd(APDU apdu) {
    receiveIncoming(apdu);
    // Arguments
    short keyparams = KMKeyParameters.exp();
    short keyFormatPtr = KMEnum.instance(KMType.KEY_FORMAT);
    short blob = KMByteBlob.exp();
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormatPtr);
    KMArray.cast(argsProto).add((short) 2, blob);

    // Decode the argument
    short args = decoder.decode(argsProto, (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET],
        bufferProp[BUF_LEN_OFFSET]);
    //reclaim memory
    repository.reclaimMemory(bufferProp[BUF_LEN_OFFSET]);

    // key params should have os patch, os version and verified root of trust
    data[KEY_PARAMETERS] = KMArray.cast(args).get((short) 0);
    tmpVariables[0] = KMArray.cast(args).get((short) 1);
    // Key format must be RAW format
    byte keyFormat = KMEnum.cast(tmpVariables[0]).getVal();
    if (keyFormat != KMType.RAW) {
      KMException.throwIt(KMError.UNIMPLEMENTED);
    }

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
    // Purpose should be VERIFY
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.PURPOSE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      if (KMEnumArrayTag.cast(tmpVariables[0]).length() != 1) {
        KMException.throwIt(KMError.INVALID_ARGUMENT);
      }
      tmpVariables[0] = KMEnumArrayTag.cast(tmpVariables[0]).get((short) 0);
      if (tmpVariables[0] != KMType.VERIFY) {
        KMException.throwIt(KMError.INCOMPATIBLE_PURPOSE);
      }
    } else {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    tmpVariables[0] = KMArray.cast(args).get((short) 2);
    // persist OEM Root Public Key.
    seProvider.persistOEMRootPublicKey(
        KMByteBlob.cast(tmpVariables[0]).getBuffer(),
        KMByteBlob.cast(tmpVariables[0]).getStartOff(),
        KMByteBlob.cast(tmpVariables[0]).length());
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
    saveAttId();
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
    KMArray.cast(tmpVariables[0]).add((short) 1, KMInteger.uint_8(provisionStatus));

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[0], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void saveAttId() {
    // clear the attestation ids.
    repository.deleteAttIds();

    short attTag = KMType.ATTESTATION_ID_BRAND;
    while (attTag <= KMType.ATTESTATION_ID_MODEL) {
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
      attTag++;
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
    // Receive the incoming request fully from the host.
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

    if (KMByteBlob.cast(data[APP_ID]).length() > KMByteTag.MAX_APP_ID_APP_DATA_SIZE
        || KMByteBlob.cast(data[APP_DATA]).length() > KMByteTag.MAX_APP_ID_APP_DATA_SIZE) {
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }
    if (!KMByteBlob.cast(data[APP_ID]).isValid()) {
      data[APP_ID] = KMType.INVALID_VALUE;
    }
    if (!KMByteBlob.cast(data[APP_DATA]).isValid()) {
      data[APP_DATA] = KMType.INVALID_VALUE;
    }
    // Check if key requires upgrade. The KeyBlob is parsed inside isKeyUpgradeRequired
    // function itself.
    if (isKeyUpgradeRequired(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad)) {
      KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
    }
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
    sendResponse(apdu, KMError.OK);
  }

  private void processDeleteKeyCmd(APDU apdu) {
    // Send ok
    sendResponse(apdu, KMError.OK);
  }

  private void processComputeSharedHmacCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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
    seProvider.createComputedHmacKey(scratchPad, (short) 0, tmpVariables[6]);

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
    setDeviceBootStatus(NEGOTIATED_SHARED_SECRET_SUCCESS);
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

  private void processUpgradeKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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

    short keyBlob = KMArray.cast(tmpVariables[2]).get((short) 0);
    data[KEY_PARAMETERS] = KMArray.cast(tmpVariables[2]).get((short) 1);
    short appId = getApplicationId(data[KEY_PARAMETERS]);
    short appData = getApplicationData(data[KEY_PARAMETERS]);

    // Check if the KeyBlob requires upgrade. The KeyBlob is parsed inside isKeyUpgradeRequired
    // function itself, but if there is a difference in the KeyBlob version isKeyUpgradeRequired()
    // does not parse the KeyBlob.
    boolean isKeyUpgradeRequired = isKeyUpgradeRequired(keyBlob, appId, appData, scratchPad);
    if (isKeyUpgradeRequired) {
      // copy origin
      data[ORIGIN] = KMEnumTag.getValue(KMType.ORIGIN, data[HW_PARAMETERS]);
      byte keyType = getKeyType(data[HW_PARAMETERS]);
      switch (keyType) {
        case ASYM_KEY_TYPE:
          data[KEY_BLOB] = KMArray.instance(ASYM_KEY_BLOB_SIZE_V1);
          KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
          break;
        case SYM_KEY_TYPE:
          data[KEY_BLOB] = KMArray.instance(SYM_KEY_BLOB_SIZE_V1);
          break;
        default:
          KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
      }
      // Update the system properties to the latest values and also re-create the KeyBlob's
      // KeyCharacteristics to make sure all the values are up-to-date with the latest applet
      // changes.
      upgradeKeyBlobKeyCharacteristics(data[HW_PARAMETERS], data[SW_PARAMETERS], scratchPad);
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
  
  // This function is only called from processUpgradeKey command.
  // 1. Update the latest values of OSVersion, OSPatch, VendorPatch and BootPatch in the
  //    KeyBlob's KeyCharacteristics.
  // 2. Re-create KeyBlob's KeyCharacteristics from HW_PARAMS to make sure we don't miss
  //    anything which happens in these functions makeSbEnforced and makeTeeEnforced in
  //    the future. Like validations.
  // 3. No need to create Keystore Enforced list here as it is not required to be included in
  //    the KeyBlob's KeyCharacteristics.
  // 4. No need to create KeyCharacteristics as upgradeKey does not require to return any
  //    KeyCharacteristics back.
  private static void upgradeKeyBlobKeyCharacteristics(short hwParams, short swParams, byte[] scratchPad) {
    short osVersion = repository.getOsVersion();
    short osPatch = repository.getOsPatch();
    short vendorPatch = repository.getVendorPatchLevel();
    short bootPatch = repository.getBootPatchLevel();
    data[HW_PARAMETERS] = KMKeyParameters.makeHwEnforced(hwParams, (byte) data[ORIGIN],
                      osVersion, osPatch, vendorPatch, bootPatch, scratchPad);
    data[SW_PARAMETERS] = KMKeyParameters.makeSwEnforced(swParams, scratchPad);
    data[KEY_CHARACTERISTICS] = KMKeyCharacteristics.instance();
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setHardwareEnforced(data[HW_PARAMETERS]);
    KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).setSoftwareEnforced(data[SW_PARAMETERS]);
  }

  private void processExportKeyCmd(APDU apdu) {
    sendResponse(apdu, KMError.UNIMPLEMENTED);
  }

  private void processImportWrappedKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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
    byte keyFormat = KMEnum.cast(tmpVariables[2]).getVal();
    if ((tmpVariables[1] == KMType.RSA || tmpVariables[1] == KMType.EC)
        && (keyFormat != KMType.PKCS8)) {
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
    // Check if key requires upgrade. The KeyBlob is parsed inside isKeyUpgradeRequired
    // function itself.
    if (isKeyUpgradeRequired(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad)) {
      KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
    }
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
    data[IMPORTED_KEY_BLOB] = KMByteBlob.instance(scratchPad, (short) 0, KMByteBlob.cast(data[INPUT_DATA]).length());
    importKey(apdu, scratchPad, keyFormat);
  }

  private void processAttestKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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
    short appId = getApplicationId(data[KEY_PARAMETERS]);
    short appData = getApplicationData(data[KEY_PARAMETERS]);
    
    // Check if key requires upgrade. The KeyBlob is parsed inside isKeyUpgradeRequired
    // function itself.
    if (isKeyUpgradeRequired(data[KEY_BLOB], appId, appData, scratchPad)) {
      KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
    }
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
    // Validate and add attestation ids.
    addAttestationIds(cert);
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
    cert.notAfter(tmpVariables[2],
        getProvisionedCertificateData(KMSEProvider.CERTIFICATE_EXPIRY),
        scratchPad,
        (short) 0);

    addTags(KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced(), true, cert);
    addTags(
        KMKeyCharacteristics.cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced(), false, cert);

    cert.deviceLocked(repository.getBootDeviceLocked());
    cert.issuer(getProvisionedCertificateData(KMSEProvider.CERTIFICATE_ISSUER));
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
  // Only add the Attestation ids which are requested in the attestation parameters.
  // If the requested attestation ids are not provisioned or deleted then
  // throw CANNOT_ATTEST_IDS error. If there is mismatch in the attestation
  // id values of both the requested parameters and the provisioned parameters
  // then throw INVALID_TAG error.
  private void addAttestationIds(KMAttestationCert cert) {
    byte index = 0;
    short attIdTag;
    short attIdTagValue;
    short storedAttId;
    while (index < (short) ATTEST_ID_TAGS.length) {
      attIdTag = KMKeyParameters.findTag(KMType.BYTES_TAG, ATTEST_ID_TAGS[index], data[KEY_PARAMETERS]);
      if (attIdTag != KMType.INVALID_VALUE) {
        attIdTagValue = KMByteTag.cast(attIdTag).getValue();
        storedAttId = repository.getAttId(mapToAttId(ATTEST_ID_TAGS[index]));
        // Return CANNOT_ATTEST_IDS if Attestation IDs are not provisioned or
        // Attestation IDs are deleted.
        if (storedAttId == KMType.INVALID_VALUE ||
            KMUtils.isEmpty(KMByteBlob.cast(storedAttId).getBuffer(),
                    KMByteBlob.cast(storedAttId).getStartOff(),
                    KMByteBlob.cast(storedAttId).length())) {
          KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
        }
        // Return CANNOT_ATTEST_IDS if Attestation IDs does not match.
        if ((KMByteBlob.cast(storedAttId).length() != KMByteBlob.cast(attIdTagValue).length()) ||
            (0 != Util.arrayCompare(KMByteBlob.cast(storedAttId).getBuffer(),
                                    KMByteBlob.cast(storedAttId).getStartOff(),
                                    KMByteBlob.cast(attIdTagValue).getBuffer(),
                                    KMByteBlob.cast(attIdTagValue).getStartOff(),
                                    KMByteBlob.cast(storedAttId).length()))) {
          KMException.throwIt(KMError.CANNOT_ATTEST_IDS);
        }
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
    sendResponse(apdu, KMError.OK);
  }

  private void processVerifyAuthorizationCmd(APDU apdu) {
    sendResponse(apdu, KMError.UNIMPLEMENTED);
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
    sendResponse(apdu, KMError.OK);
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
    	  finishTrustedConfirmationOperation(op);
      case KMType.VERIFY:
        finishSigningVerifyingOperation(op, scratchPad);
        break;
      case KMType.ENCRYPT:
        finishEncryptOperation(op);
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

  private void finishEncryptOperation(KMOperationState op) {
    if(op.getAlgorithm() != KMType.AES && op.getAlgorithm() != KMType.DES){
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    finishAesDesOperation(op);
  }
  
  private void finishAesDesOperation(KMOperationState op) {
    short len = KMByteBlob.cast(data[INPUT_DATA]).length();
    short blockSize = DES_BLOCK_SIZE;
    if (op.getAlgorithm() == KMType.AES) {
      blockSize = AES_BLOCK_SIZE;
    }

    if((op.getPurpose() == KMType.DECRYPT) && (op.getPadding() == KMType.PKCS7)
        && (op.getBlockMode() == KMType.ECB || op.getBlockMode() == KMType.CBC)
        && ((short) (len % blockSize) != 0)){
      KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
    }

    if (op.getBlockMode() == KMType.GCM) {
      if (op.getPurpose() == KMType.DECRYPT && (len < (short) (op.getMacLength() / 8))) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
      // update aad if there is any
      updateAAD(op, (byte) 0x01);
      // Get the output size
      len = op.getOperation().getAESGCMOutputSize(len, (short) (op.getMacLength() / 8));
    }
    // If padding i.e. pkcs7 then add padding to right
    // Output data can at most one block size more the input data in case of pkcs7
    // encryption
    data[OUTPUT_DATA] = KMByteBlob.instance((short) (len + 2 * blockSize));
    try {
      len = op.getOperation().finish(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          KMByteBlob.cast(data[INPUT_DATA]).length(),
          KMByteBlob.cast(data[OUTPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[OUTPUT_DATA]).getStartOff());
    } catch (CryptoException e) {
      if (e.getReason() == CryptoException.ILLEGAL_USE) {
        KMException.throwIt(KMError.INVALID_INPUT_LENGTH);
      }
    }

    // Update the length of the output
    KMByteBlob.cast(data[OUTPUT_DATA]).setLength(len);
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
        finishAesDesOperation(op);
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
      // Validate Verification Token.
      validateVerificationToken(data[VERIFICATION_TOKEN], scratchPad);
      // validate operation handle.
      short ptr = KMVerificationToken.cast(data[VERIFICATION_TOKEN]).getChallenge();
      if (KMInteger.compare(ptr, op.getHandle()) != 0) {
        KMException.throwIt(KMError.VERIFICATION_FAILED);
      }
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
      if (!authTokenMatches(op.getUserSecureId(), op.getAuthType(), scratchPad)) {
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
    }
  }

  private void authorizeKeyUsageForCount(byte[] scratchPad) {
    short scratchPadOff = 0;
    Util.arrayFillNonAtomic(scratchPad, scratchPadOff, (short) 12, (byte) 0);

    short usageLimitBufLen = KMIntegerTag.getValue(scratchPad, scratchPadOff,
        KMType.UINT_TAG, KMType.MAX_USES_PER_BOOT, data[HW_PARAMETERS]);

    if (usageLimitBufLen == KMType.INVALID_VALUE) {
      return;
    }

    if (usageLimitBufLen > 4) {
      KMException.throwIt(KMError.INVALID_ARGUMENT);
    }

    if (repository.isAuthTagPersisted(data[AUTH_TAG])) {
      // Get current counter, update and increment it.
      short len = repository
          .getRateLimitedKeyCount(data[AUTH_TAG], scratchPad, (short) (scratchPadOff + 4));
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

      repository
          .setRateLimitedKeyCount(data[AUTH_TAG], scratchPad, (short) (scratchPadOff + len * 2),
              len);

    } else {
      // Persist auth tag.
      if (!repository.persistAuthTag(data[AUTH_TAG])) {
        KMException.throwIt(KMError.TOO_MANY_OPERATIONS);
      }
    }
  }


  private void authorizeDeviceUnlock(byte[] scratchPad) {
    // If device is locked and key characteristics requires unlocked device then check whether
    // HW auth token has correct timestamp.
    short ptr =
        KMKeyParameters.findTag(
            KMType.BOOL_TAG, KMType.UNLOCKED_DEVICE_REQUIRED, data[HW_PARAMETERS]);

    if (ptr != KMType.INVALID_VALUE && repository.getDeviceLock()) {
      if (!validateHwToken(data[HW_TOKEN], scratchPad)) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      ptr = KMHardwareAuthToken.cast(data[HW_TOKEN]).getTimestamp();
      // Check if the current auth time stamp is greater then device locked time stamp
      short ts = repository.getDeviceTimeStamp();
      if (KMInteger.compare(ptr, ts) <= 0) {
        KMException.throwIt(KMError.DEVICE_LOCKED);
      }
      // Now check if the device unlock requires password only authentication and whether
      // auth token is generated through password authentication or not.
      if (repository.getDeviceLockPasswordOnly()) {
        ptr = KMHardwareAuthToken.cast(data[HW_TOKEN]).getHwAuthenticatorType();
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

  private boolean verifyVerificationTokenMacInBigEndian(short verToken, byte[] scratchPad) {
    // concatenation length will be 37 + length of verified parameters list - which
    // is typically
    // empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopyNonAtomic(authVerification, (short) 0, scratchPad, (short) 0, (short) authVerification.length);
    short len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr).value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr).value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate security level - 4 bytes
    ptr = KMVerificationToken.cast(verToken).getSecurityLevel();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += KMInteger.UINT_32;
    // concatenate Parameters verified - blob of encoded data.
    ptr = KMVerificationToken.cast(verToken).getParametersVerified();
    if (KMByteBlob.cast(ptr).length() != 0) {
      len += KMByteBlob.cast(ptr).getValues(scratchPad, (short) 0);
    }
    // hmac the data
    ptr = KMVerificationToken.cast(verToken).getMac();

    return seProvider.hmacVerify(
        seProvider.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
  }

  private boolean verifyVerificationTokenMacInLittleEndian(short verToken, byte[] scratchPad) {
    // concatenation length will be 37 + length of verified parameters list - which
    // is typically
    // empty
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    // Add "Auth Verification" - 17 bytes.
    Util.arrayCopyNonAtomic(authVerification, (short) 0, scratchPad, (short) 0, (short) authVerification.length);
    short len = (short) authVerification.length;
    // concatenate challenge - 8 bytes
    short ptr = KMVerificationToken.cast(verToken).getChallenge();
    KMInteger.cast(ptr).toLittleEndian(scratchPad, len);
    len += KMInteger.UINT_64;
    // concatenate timestamp -8 bytes
    ptr = KMVerificationToken.cast(verToken).getTimestamp();
    KMInteger.cast(ptr).toLittleEndian(scratchPad, len);
    len += KMInteger.UINT_64;
    // concatenate security level - 4 bytes
    ptr = KMVerificationToken.cast(verToken).getSecurityLevel();
    scratchPad[len] = KMEnum.cast(ptr).getVal();
    len += KMInteger.UINT_32;
    // concatenate Parameters verified - blob of encoded data.
    ptr = KMVerificationToken.cast(verToken).getParametersVerified();
    if (KMByteBlob.cast(ptr).length() != 0) {
      len += KMByteBlob.cast(ptr).getValues(scratchPad, (short) 0);
    }
    // hmac the data
    ptr = KMVerificationToken.cast(verToken).getMac();

    return seProvider.hmacVerify(
        seProvider.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
  }

  private void validateVerificationToken(short verToken, byte[] scratchPad) {
    short ptr = KMVerificationToken.cast(verToken).getMac();
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      KMException.throwIt(KMError.INVALID_MAC_LENGTH);
    }
    boolean verify;
    if (KMConfigurations.TEE_MACHINE_TYPE == KMConfigurations.LITTLE_ENDIAN) {
      verify = verifyVerificationTokenMacInLittleEndian(verToken, scratchPad);
    } else {
      verify = verifyVerificationTokenMacInBigEndian(verToken, scratchPad);
    }
    if (!verify) {
      // Throw Exception if none of the combination works.
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
    short inputConsumed = 0;
    // If signing without  digest then do length validation checks
    if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY) {
      tmpVariables[0] = KMByteBlob.cast(data[INPUT_DATA]).length();
      // update the data.
      op.getOperation()
          .update(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length());
      // update trusted confirmation operation
      updateTrustedConfirmationOperation(op);
      
      data[OUTPUT_DATA] = KMType.INVALID_VALUE;
    } else if (op.getPurpose() == KMType.ENCRYPT || op.getPurpose() == KMType.DECRYPT) {
      // Update for encrypt/decrypt using RSA will not be supported because to do this op state
      //  will have to buffer the data - so reject the update if it is rsa algorithm.
      if (op.getAlgorithm() == KMType.RSA) {
        KMException.throwIt(KMError.OPERATION_CANCELLED);
      }
      short inputLen = KMByteBlob.cast(data[INPUT_DATA]).length();
      short blockSize = DES_BLOCK_SIZE;
      if (op.getAlgorithm() == KMType.AES) {
          blockSize = AES_BLOCK_SIZE;
          if (op.getBlockMode() == KMType.GCM) {
            updateAAD(op, (byte) 0x00);
            // if input data present
            if (inputLen > 0) {
              // no more future updateAAD allowed if input data present.
              if (op.isAesGcmUpdateAllowed()) {
                op.setAesGcmUpdateComplete();
              }
            }
          }
      } 
      // Allocate output buffer as input data is already block aligned
      data[OUTPUT_DATA] = KMByteBlob.instance((short) (inputLen + 2 * blockSize));
      // Otherwise just update the data.
      // HAL consumes all the input and maintains a buffered data inside it. So the
      // applet sends the inputConsumed length as same as the input length.
      inputConsumed = inputLen;
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
      KMByteBlob.cast(data[OUTPUT_DATA]).setLength(tmpVariables[0]);
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
    KMArray.cast(tmpVariables[2]).add((short) 1, KMInteger.uint_16(inputConsumed));
    KMArray.cast(tmpVariables[2]).add((short) 2, tmpVariables[1]);
    KMArray.cast(tmpVariables[2]).add((short) 3, data[OUTPUT_DATA]);

    bufferProp[BUF_START_OFFSET] = repository.allocAvailableMemory();
    // Encode the response
    bufferProp[BUF_LEN_OFFSET] = encoder.encode(tmpVariables[2], (byte[]) bufferRef[0], bufferProp[BUF_START_OFFSET]);
    sendOutgoing(apdu);
  }

  private void processBeginOperationCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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
    data[APP_ID] = getApplicationId(data[KEY_PARAMETERS]);
    data[APP_DATA] = getApplicationData(data[KEY_PARAMETERS]);
    // Check if key requires upgrade. The KeyBlob is parsed inside isKeyUpgradeRequired
    // function itself.
    if (isKeyUpgradeRequired(data[KEY_BLOB], data[APP_ID], data[APP_DATA], scratchPad)) {
      KMException.throwIt(KMError.KEY_REQUIRES_UPGRADE);
    }
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
     	beginTrustedConfirmationOperation(op);
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
        Util.arrayCopyNonAtomic(
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

  private boolean isDigestSupported(byte alg, byte digest) {
    switch (alg) {
    case KMType.RSA:
    case KMType.EC:
      if (digest != KMType.DIGEST_NONE && digest != KMType.SHA2_256) {
        return false;
      }
      break;
    case KMType.HMAC:
      if (digest != KMType.SHA2_256) {
        return false;
      }
      break;
    default:
      break;
    }
    return true;
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
        if (param == KMType.INVALID_VALUE ||
            !isDigestSupported(op.getAlgorithm(), op.getDigest())) {
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
        KMException.throwIt(KMError.UNSUPPORTED_PADDING_MODE);
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
        if ((param == KMType.PADDING_NONE || param == KMType.RSA_PKCS1_1_5_ENCRYPT)
            && op.getDigest() != KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if ((param == KMType.RSA_OAEP || param == KMType.RSA_PSS)
            && op.getDigest() == KMType.DIGEST_NONE) {
          KMException.throwIt(KMError.INCOMPATIBLE_DIGEST);
        }
        if (op.getPurpose() == KMType.SIGN || op.getPurpose() == KMType.VERIFY
            || param == KMType.RSA_OAEP) {
          // Digest is mandatory in these cases.
          if (!isDigestSupported(op.getAlgorithm(), op.getDigest())) {
            KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
          }
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
              || macLen > 128) {
        	  KMException.throwIt(KMError.UNSUPPORTED_MAC_LENGTH);
          }
          if(macLen
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
          }
          if (macLen % 8 != 0
                  || macLen > 256) {
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
    authorizeUserSecureIdAuthTimeout(op, scratchPad);
    authorizeDeviceUnlock(scratchPad);
    authorizeKeyUsageForCount(scratchPad);
    
    //Validate bootloader only 
    tmpVariables[0] =
            KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.BOOTLOADER_ONLY, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
    	KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    
  //Validate early boot
    tmpVariables[0] =
            KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, data[HW_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE && repository.getEarlyBootEndedStatus()) {
    	KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }

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
  
  private void beginTrustedConfirmationOperation(KMOperationState op) {
    // Check for trusted confirmation - if required then set the signer in op state.
    if (KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.TRUSTED_CONFIRMATION_REQUIRED,
        data[HW_PARAMETERS]) != KMType.INVALID_VALUE) {

      op.setTrustedConfirmationSigner(
          seProvider.initTrustedConfirmationSymmetricOperation(seProvider.getComputedHmacKey()));

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

  private void authorizeUserSecureIdAuthTimeout(KMOperationState op, byte[] scratchPad) {
    short authTime;
    short authType;
    // Authorize User Secure Id and Auth timeout
    short userSecureIdPtr =
        KMKeyParameters.findTag(KMType.ULONG_ARRAY_TAG, KMType.USER_SECURE_ID, data[HW_PARAMETERS]);
    if (userSecureIdPtr != KMType.INVALID_VALUE) {
      // Authentication required.
      if (KMType.INVALID_VALUE !=
          KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.NO_AUTH_REQUIRED, data[HW_PARAMETERS])) {
        // Key has both USER_SECURE_ID and NO_AUTH_REQUIRED
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
      }
      // store authenticator type
      if(KMType.INVALID_VALUE ==
          (authType = KMEnumTag.getValue(KMType.USER_AUTH_TYPE, data[HW_PARAMETERS]))) {
        // Authentication required, but no auth type found.
        KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
      }
      
      short authTimeoutTagPtr =
          KMKeyParameters.findTag(KMType.UINT_TAG, KMType.AUTH_TIMEOUT, data[HW_PARAMETERS]);
      if (authTimeoutTagPtr != KMType.INVALID_VALUE) {
        // authenticate user
        if (!authTokenMatches(userSecureIdPtr, authType, scratchPad)) {
          KMException.throwIt(KMError.KEY_USER_NOT_AUTHENTICATED);
        }

        authTimeoutTagPtr =
            KMKeyParameters.findTag(KMType.ULONG_TAG, KMType.AUTH_TIMEOUT_MILLIS, data[CUSTOM_TAGS]);
        if (authTimeoutTagPtr == KMType.INVALID_VALUE) {
          KMException.throwIt(KMError.INVALID_KEY_BLOB);
        }
        authTime = KMIntegerTag.cast(authTimeoutTagPtr).getValue();
        // set the one time auth
        op.setOneTimeAuthReqd(true);
        // set the authentication time stamp in operation state
        authTime =
            addIntegers(authTime,
                KMHardwareAuthToken.cast(data[HW_TOKEN]).getTimestamp(), scratchPad);
        op.setAuthTime(
            KMInteger.cast(authTime).getBuffer(), KMInteger.cast(authTime).getStartOff());
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

  private boolean isHwAuthTokenContainsMatchingSecureId(short hwAuthToken,
      short secureUserIdsObj) {
    short secureUserId = KMHardwareAuthToken.cast(hwAuthToken).getUserId();
    if (!KMInteger.cast(secureUserId).isZero()) {
      if (KMIntegerArrayTag.cast(secureUserIdsObj).contains(secureUserId))
        return true;
    }

    short authenticatorId = KMHardwareAuthToken.cast(hwAuthToken).getAuthenticatorId();
    if (!KMInteger.cast(authenticatorId).isZero()) {
      if (KMIntegerArrayTag.cast(secureUserIdsObj).contains(authenticatorId))
        return true;
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
    tmpVariables[2] = KMHardwareAuthToken.cast(data[HW_TOKEN]).getHwAuthenticatorType();
    tmpVariables[2] = KMEnum.cast(tmpVariables[2]).getVal();
    if (((byte) tmpVariables[2] & (byte) authType) == 0) {
      return false;
    }
    return true;
  }

  private boolean verifyHwTokenMacInBigEndian(short hwToken, byte[] scratchPad) {
    // The challenge, userId and authenticatorId, authenticatorType and timestamp
    // are in network order (big-endian).
    short len = 0;
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
    KMInteger.cast(ptr)
    .value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getUserId();
    KMInteger.cast(ptr)
    .value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
    KMInteger.cast(ptr)
    .value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += KMInteger.UINT_32;
    // concatenate timestamp -8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
    KMInteger.cast(ptr)
        .value(scratchPad, (short) (len + (short) (KMInteger.UINT_64 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;

    ptr = KMHardwareAuthToken.cast(hwToken).getMac();

    return seProvider.hmacVerify(
        seProvider.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());

  }
  
  private boolean verifyHwTokenMacInLittleEndian(short hwToken, byte[] scratchPad) {
    // The challenge, userId and authenticatorId values are in little endian order, 
    // but authenticatorType and timestamp are in network order (big-endian).
    short len = 0;
    // add 0
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 256, (byte) 0);
    len = 1;
    // concatenate challenge - 8 bytes
    short ptr = KMHardwareAuthToken.cast(hwToken).getChallenge();
    KMInteger.cast(ptr).toLittleEndian(scratchPad, len);
    len += KMInteger.UINT_64;
    // concatenate user id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getUserId();
    KMInteger.cast(ptr).toLittleEndian(scratchPad, len);
    len += KMInteger.UINT_64;
    // concatenate authenticator id - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getAuthenticatorId();
    KMInteger.cast(ptr).toLittleEndian(scratchPad, len);
    len += KMInteger.UINT_64;
    // concatenate authenticator type - 4 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getHwAuthenticatorType();
    scratchPad[(short) (len + 3)] = KMEnum.cast(ptr).getVal();
    len += KMInteger.UINT_32;
    // concatenate timestamp - 8 bytes
    ptr = KMHardwareAuthToken.cast(hwToken).getTimestamp();
    KMInteger.cast(ptr)
    .value(scratchPad, (short) (len + (short) (8 - KMInteger.cast(ptr).length())));
    len += KMInteger.UINT_64;

    ptr = KMHardwareAuthToken.cast(hwToken).getMac();

    return seProvider.hmacVerify(
        seProvider.getComputedHmacKey(),
        scratchPad,
        (short) 0,
        len,
        KMByteBlob.cast(ptr).getBuffer(),
        KMByteBlob.cast(ptr).getStartOff(),
        KMByteBlob.cast(ptr).length());
  }

  private boolean validateHwToken(short hwToken, byte[] scratchPad) {
    // CBOR Encoding is always big endian
    short ptr = KMHardwareAuthToken.cast(hwToken).getMac();
    // If mac length is zero then token is empty.
    if (KMByteBlob.cast(ptr).length() == 0) {
      return false;
    }
    if (KMConfigurations.TEE_MACHINE_TYPE == KMConfigurations.LITTLE_ENDIAN) {
      return verifyHwTokenMacInLittleEndian(hwToken, scratchPad);
    } else {
      return verifyHwTokenMacInBigEndian(hwToken, scratchPad);
    }
  }

  private void processImportKeyCmd(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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

    byte keyFormat = KMEnum.cast(tmpVariables[3]).getVal();

    short alg = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);   
    if((alg == KMType.AES || alg == KMType.DES || alg == KMType.HMAC) && keyFormat != KMType.RAW ) {
        KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    if((alg == KMType.RSA || alg == KMType.EC) && keyFormat != KMType.PKCS8){
        KMException.throwIt(KMError.UNIMPLEMENTED);
    }
    
    data[ORIGIN] = KMType.IMPORTED;
    importKey(apdu, scratchPad, keyFormat);
  }

  private void importKey(APDU apdu, byte[] scratchPad, byte keyFormat) {
    // Check if the purpose is ATTEST_KEY.
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.ATTEST_KEY, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }

    tmpVariables[0] =
            KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE && repository.getEarlyBootEndedStatus()) {
      KMException.throwIt(KMError.EARLY_BOOT_ENDED);
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
        importECKeys(scratchPad, keyFormat);
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
        break;
    }
    // make key characteristics - returns key characteristics in data[KEY_CHARACTERISTICS]
    makeKeyCharacteristics(scratchPad);
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

  private void decodeRawECKey() {
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
  }

  private void decodePKCS8ECKeys() {
    // Decode key material
    short keyBlob = seProvider.getPKCS8DecoderInstance().decodeEc(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.cast(keyBlob).get((short) 0);
    data[SECRET] = KMArray.cast(keyBlob).get((short) 1);
  }

  private void importECKeys(byte[] scratchPad, byte keyFormat) {
    if (keyFormat == KMType.RAW) {
      decodeRawECKey();
    } else {
      decodePKCS8ECKeys();
    }
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
      if (!(256 <= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))
    	          && (383 >= (short) (KMByteBlob.cast(data[SECRET]).length() * 8))){
    	  KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }	
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
    data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private void importHmacKey(byte[] scratchPad) {
    // Get Key
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (!(tmpVariables[2] >= 64 && tmpVariables[2] <= 512 && tmpVariables[2] % 8 == 0)) {
    	  KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      if (tmpVariables[2] != (short) (KMByteBlob.cast(data[SECRET]).length() * 8)) {
        KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad
      tmpVariables[6] =	(short) (KMByteBlob.cast(data[SECRET]).length() * 8);
      if (!(tmpVariables[6] >= 64 && tmpVariables[6] <= 512 && tmpVariables[6] % 8 == 0)) {
    	  KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      tmpVariables[5] = KMInteger.uint_16(tmpVariables[6]);
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

    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
  }

  private void importTDESKey(byte[] scratchPad) {
    // Decode Key Material
    data[SECRET] = data[IMPORTED_KEY_BLOB];
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    tmpVariables[2] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[2] != KMType.INVALID_VALUE) {
      if (tmpVariables[2] != 168 ||
    		  192 != (short)( 8 * KMByteBlob.cast(data[SECRET]).length())) {
          KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
    } else {
      // add the key size to scratchPad 
      tmpVariables[6] = (short)( 8 * KMByteBlob.cast(data[SECRET]).length());
      if(tmpVariables[6] != 192) {
    	  KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
      }
      tmpVariables[5] = KMInteger.uint_16(tmpVariables[6]);
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
    // Read Minimum Mac length - it must not be present
    // Added this error check based on default reference implementation.
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
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
    tmpVariables[4] = 0; // index in scratchPad for update params
    // check the keysize tag if present in key parameters.
    short keysize =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);

    if (keysize != KMType.INVALID_VALUE) {
      if(keysize != (short)( 8 * KMByteBlob.cast(data[SECRET]).length())) {
    	KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
      }
      validateAesKeySize(keysize);
    } else {
      // add the key size to scratchPad
      keysize = (short) ( 8 * KMByteBlob.cast(data[SECRET]).length());
      validateAesKeySize(keysize);
      keysize = KMInteger.uint_16(keysize);
      short keysizeTag = KMIntegerTag.instance(KMType.UINT_TAG, KMType.KEYSIZE, keysize);
      Util.setShort(scratchPad, tmpVariables[4], keysizeTag);
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
    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
  }

  private void importRSAKey(byte[] scratchPad) {
    // Decode key material
    short keyblob = seProvider.getPKCS8DecoderInstance().decodeRsa(data[IMPORTED_KEY_BLOB]);
    data[PUB_KEY] = KMArray.cast(keyblob).get((short) 0);
    short pubKeyExp = KMArray.cast(keyblob).get((short)1);
    data[SECRET] = KMArray.cast(keyblob).get((short) 2);
    
    if(F4.length != KMByteBlob.cast(pubKeyExp).length()) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    if(Util.arrayCompare(F4, (short)0, KMByteBlob.cast(pubKeyExp).getBuffer(),
        KMByteBlob.cast(pubKeyExp).getStartOff(), (short)F4.length) != 0) {
      KMException.throwIt(KMError.IMPORT_PARAMETER_MISMATCH);
    }
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
      tmpVariables[6] = (short) (KMByteBlob.cast(data[SECRET]).length() * 8);	
      if(tmpVariables[6] != 2048) {
    	  KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE); 
      }
      tmpVariables[5] = KMInteger.uint_16((short) tmpVariables[6]);
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
    data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);
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
    repository.setBootDeviceLocked(enumVal == KMType.DEVICE_LOCKED_TRUE);

    // Clear the Computed SharedHmac and Hmac nonce from persistent memory.
    Util.arrayFillNonAtomic(scratchPad, (short) 0, KMRepository.COMPUTED_HMAC_KEY_SIZE, (byte) 0);
    seProvider.createComputedHmacKey(scratchPad, (short) 0, KMRepository.COMPUTED_HMAC_KEY_SIZE);
    repository.clearHmacNonce();

    //Clear all the operation state.
    repository.releaseAllOperations();

    // Hmac is cleared, so generate a new Hmac nonce.
    seProvider.newRandomNumber(scratchPad, (short) 0, KMRepository.HMAC_SEED_NONCE_SIZE);
    repository.initHmacNonce(scratchPad, (short) 0, KMRepository.HMAC_SEED_NONCE_SIZE);
    
    //flag to maintain early boot ended state
    repository.setEarlyBootEndedStatus(false);
    
    // Clear all the auth tags
    repository.removeAllAuthTags();
  }

  private static void processGenerateKey(APDU apdu) {
    // Receive the incoming request fully from the host into buffer.
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
    // Check if the purpose is ATTEST_KEY.
    if (KMEnumArrayTag.contains(KMType.PURPOSE, KMType.ATTEST_KEY, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_PURPOSE);
    }
    // Check if EarlyBootEnded tag is present.
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.EARLY_BOOT_ONLY, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE && repository.getEarlyBootEndedStatus()) {
      KMException.throwIt(KMError.EARLY_BOOT_ENDED);
    }
    // Check if rollback resistance tag is present
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.BOOL_TAG, KMType.ROLLBACK_RESISTANCE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.ROLLBACK_RESISTANCE_UNAVAILABLE);
    }
    
    // get algorithm
    tmpVariables[3] = KMEnumTag.getValue(KMType.ALGORITHM, data[KEY_PARAMETERS]);
    if (tmpVariables[3] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
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
    // make key characteristics - returns key characteristics in data[KEY_CHARACTERISTICS]
    makeKeyCharacteristics(scratchPad);
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

    data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateAESKey() {
    // Read key size
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMTag.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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
          KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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
    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
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
    data[KEY_BLOB] = createKeyBlobInstance(ASYM_KEY_TYPE);;
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_PUB_KEY, data[PUB_KEY]);
  }

  private static void validateTDESKey() {
    // Read Minimum Mac length - it must not be present
    // This below check is done based on the reference implementation.
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] != KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.INVALID_TAG);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
    if (tmpVariables[1] != 168) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
    }
  }

  private static void generateTDESKey(byte[] scratchPad) {
    validateTDESKey();
    tmpVariables[0] = seProvider.createSymmetricKey(KMType.DES, (short) 168, scratchPad, (short) 0);
    data[SECRET] = KMByteBlob.instance(scratchPad, (short) 0, tmpVariables[0]);
    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
  }

  private static void validateHmacKey() {
    // If params does not contain any digest throw unsupported digest error.
    tmpVariables[0] =
        KMKeyParameters.findTag(KMType.ENUM_ARRAY_TAG, KMType.DIGEST, data[KEY_PARAMETERS]);
    if (KMType.INVALID_VALUE == tmpVariables[0]) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Strongbox supports only SHA256.
    if (!KMEnumArrayTag.contains(KMType.DIGEST, KMType.SHA2_256, data[KEY_PARAMETERS])) {
      KMException.throwIt(KMError.UNSUPPORTED_DIGEST);
    }
    // Read Minimum Mac length
    tmpVariables[0] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.MIN_MAC_LENGTH, data[KEY_PARAMETERS]);
    if (tmpVariables[0] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.MISSING_MIN_MAC_LENGTH);
    }
    // Check whether digest size is greater than or equal to min mac length.
    // This below check is done based on the reference implementation.
    if (((short) (tmpVariables[0] % 8) != 0)
        || (tmpVariables[0] < (short) 64)
        || tmpVariables[0] > (short) 256) {
      KMException.throwIt(KMError.UNSUPPORTED_MIN_MAC_LENGTH);
    }
    // Read keysize
    tmpVariables[1] =
        KMIntegerTag.getShortValue(KMType.UINT_TAG, KMType.KEYSIZE, data[KEY_PARAMETERS]);
    if (tmpVariables[1] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNSUPPORTED_KEY_SIZE);
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
    data[KEY_BLOB] = createKeyBlobInstance(SYM_KEY_TYPE);
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
    // make root of trust blob
    data[ROT] = repository.readROT(KEYBLOB_CURRENT_VERSION);
    if (data[ROT] == KMType.INVALID_VALUE) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }

    // make hidden key params list
    data[HIDDEN_PARAMETERS] =
        KMKeyParameters.makeHidden(data[KEY_PARAMETERS], data[ROT], scratchPad);
    data[KEY_BLOB_VERSION_DATA_OFFSET] = KMInteger.uint_16(KEYBLOB_CURRENT_VERSION);
    // create custom tags
    data[CUSTOM_TAGS] = KMKeyParameters.makeCustomTags(data[HW_PARAMETERS], scratchPad);
    // make authorization data
    makeAuthData(KEYBLOB_CURRENT_VERSION, scratchPad);
    // encrypt the secret and cryptographically attach that to authorization data
    encryptSecret(scratchPad);

    // create key blob array
    //KMArray.cast(ENC_TRANSPORT_KEY);   
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_SECRET, data[SECRET]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_AUTH_TAG, data[AUTH_TAG]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_NONCE, data[NONCE]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_VERSION_OFFSET, data[KEY_BLOB_VERSION_DATA_OFFSET]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_KEYCHAR, data[KEY_CHARACTERISTICS]);
    KMArray.cast(data[KEY_BLOB]).add(KEY_BLOB_CUSTOM_TAGS, data[CUSTOM_TAGS]);

    tmpVariables[0] = repository.alloc((short) 1024);
    tmpVariables[1] = encoder.encode(data[KEY_BLOB], repository.getHeap(), tmpVariables[0]);
    data[KEY_BLOB] = KMByteBlob.instance(repository.getHeap(), tmpVariables[0], tmpVariables[1]);
  }

  private void parseEncryptedKeyBlob(short keyBlob, short appId, short appData,
	      byte[] scratchPad, short version) {
    // make root of trust blob
	data[ROT] = repository.readROT(version);
	if (data[ROT] == KMType.INVALID_VALUE) {
	  KMException.throwIt(KMError.UNKNOWN_ERROR);
	}
    try {
      decodeKeyBlob(version, keyBlob);
      processDecryptSecret(version, appId, appData, scratchPad);
    } catch (Exception e) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
  }
  
  private void decodeKeyBlob(short version, short keyBlob) {
    // Decode KeyBlob and read the KeyBlob params based on the version.
    short parsedBlob = decoder.decodeArray(createKeyBlobExp(version),
        KMByteBlob.cast(keyBlob).getBuffer(),
        KMByteBlob.cast(keyBlob).getStartOff(),
        KMByteBlob.cast(keyBlob).length());
    short minArraySize = 0;
    switch(version) {
    case 0:
      minArraySize = SYM_KEY_BLOB_SIZE_V0;
      break;
    case 1:
      minArraySize = SYM_KEY_BLOB_SIZE_V1;
      break;
    default:
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    };
    // KeyBlob size should not be less than the minimum KeyBlob size.
    if (KMArray.cast(parsedBlob).length() < minArraySize) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    readKeyBlobParams(version, parsedBlob);
  }
  
  private void readKeyBlobParams(short version, short parsedKeyBlob) {
    data[KEY_BLOB] = parsedKeyBlob;
    // initialize data
    switch (version) {
      case (short) 0:
        data[SECRET] = KMArray.cast(parsedKeyBlob).get((short) 0);
        data[NONCE]= KMArray.cast(parsedKeyBlob).get((short) 1);
        data[AUTH_TAG] = KMArray.cast(parsedKeyBlob).get((short) 2);
        data[KEY_CHARACTERISTICS] = KMArray.cast(parsedKeyBlob).get((short) 3);
        data[PUB_KEY] = KMType.INVALID_VALUE;
        if (KMArray.cast(parsedKeyBlob).length() == ASYM_KEY_BLOB_SIZE_V0) {
          data[PUB_KEY] = KMArray.cast(parsedKeyBlob).get((short) 4);
        }
        // Set the data[KEY_BLOB_VERSION_DATA_OFFSET] with integer value of 0 so
        // that it will used at later point of time.
        data[KEY_BLOB_VERSION_DATA_OFFSET] = KMInteger.uint_8((byte) 0);
        break;
      case (short) 1:
        data[SECRET] = KMArray.cast(parsedKeyBlob).get(KEY_BLOB_SECRET);
        data[NONCE]= KMArray.cast(parsedKeyBlob).get(KEY_BLOB_NONCE);
        data[AUTH_TAG] = KMArray.cast(parsedKeyBlob).get(KEY_BLOB_AUTH_TAG);
        data[KEY_CHARACTERISTICS] = KMArray.cast(parsedKeyBlob).get(KEY_BLOB_KEYCHAR);
        data[KEY_BLOB_VERSION_DATA_OFFSET] = KMArray.cast(parsedKeyBlob).get(
            KEY_BLOB_VERSION_OFFSET);
        data[CUSTOM_TAGS] = KMArray.cast(parsedKeyBlob).get(
            KEY_BLOB_CUSTOM_TAGS);
        data[PUB_KEY] = KMType.INVALID_VALUE;
        if (KMArray.cast(parsedKeyBlob).length() == ASYM_KEY_BLOB_SIZE_V1) {
          data[PUB_KEY] = KMArray.cast(parsedKeyBlob).get(KEY_BLOB_PUB_KEY);
        }
        break;
      default:
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
  }
  
  private void processDecryptSecret(short version, short appId, short appData, byte[] scratchPad) {
   data[HW_PARAMETERS] = KMKeyCharacteristics
              .cast(data[KEY_CHARACTERISTICS]).getHardwareEnforced();
   data[SW_PARAMETERS] = KMKeyCharacteristics
              .cast(data[KEY_CHARACTERISTICS]).getSoftwareEnforced();
   data[HIDDEN_PARAMETERS] = KMKeyParameters.makeHidden(appId, appData, data[ROT], scratchPad);
    // make auth data
    makeAuthData(version, scratchPad);
    // Decrypt Secret and verify auth tag
    decryptSecret(scratchPad);
    short keyBlobSecretOff = 0;
    switch(version) {
    case 0:
      // V0 KeyBlob
      // KEY_BLOB = [
      //     SECRET, 
      //     NONCE, 
      //     AUTH_TAG, 
      //     KEY_CHARACTERISTICS,
      //     PUBKEY
      // ]
      keyBlobSecretOff = (short) 0;
      break;
    case 1:
      // V1 KeyBlob
      // KEY_BLOB = [
      //     VERSION,   
      //     SECRET, 
      //     NONCE, 
      //     AUTH_TAG, 
      //     KEY_CHARACTERISTICS,
      //     CUSTOM_TAGS
      //     PUBKEY
      // ]
      keyBlobSecretOff = (short) 1;
      break;
    default:
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    };
    KMArray.cast(data[KEY_BLOB]).add(keyBlobSecretOff, data[SECRET]);
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

  private static byte getKeyType(short hardwareParams) {
    short alg = KMKeyParameters.findTag(KMType.ENUM_TAG, KMType.ALGORITHM, hardwareParams);
    if (KMEnumTag.cast(alg).getValue() == KMType.RSA
        || KMEnumTag.cast(alg).getValue() == KMType.EC) {
      return ASYM_KEY_TYPE;
    }
    return SYM_KEY_TYPE;
  }
 
  private static void makeAuthData(short version, byte[] scratchPad) {
    // For KeyBlob V1: Auth Data includes HW_PARAMETERS, SW_PARAMTERS, HIDDEN_PARAMETERS, CUSTOM_TAGS, VERSION and PUB_KEY.
    // For KeyBlob V0: Auth Data includes HW_PARAMETERS, SW_PARAMTERS, HIDDEN_PARAMETERS and PUB_KEY.
    // VERSION is included only for KeyBlobs having version >= 1.
    // PUB_KEY is included for only ASYMMETRIC KeyBlobs.
    short index = 0;
    short numParams = 0;
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 12, (byte) 0);
    byte keyType = getKeyType(data[HW_PARAMETERS]);
    // Copy the relevant parameters in the scratchPad in the order
    // 1. HW_PARAMETERS
    // 2. HIDDEN_PARAMETERS
    // 3. VERSION ( Only Version >= 1)
    // 4. PUB_KEY ( Only for Asymmetric Keys)
    switch (version) {
      case (short) 0:
        numParams = 3;
        Util.setShort(scratchPad, (short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
        Util.setShort(scratchPad, (short) 2, KMKeyParameters.cast(data[SW_PARAMETERS]).getVals());
        Util.setShort(scratchPad, (short) 4, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
        // For Asymmetric Keys include the PUB_KEY.
        if (keyType == ASYM_KEY_TYPE) {
          numParams = 4;
          Util.setShort(scratchPad, (short) 6, data[PUB_KEY]);
        }
        break;
      case (short) 1:
        numParams = 5;
        Util.setShort(scratchPad, (short) 0, KMKeyParameters.cast(data[HW_PARAMETERS]).getVals());
        Util.setShort(scratchPad, (short) 2, KMKeyParameters.cast(data[SW_PARAMETERS]).getVals());
        Util.setShort(scratchPad, (short) 4, KMKeyParameters.cast(data[HIDDEN_PARAMETERS]).getVals());
        Util.setShort(scratchPad, (short) 6, KMKeyParameters.cast(data[CUSTOM_TAGS]).getVals());
        Util.setShort(scratchPad, (short) 8, data[KEY_BLOB_VERSION_DATA_OFFSET]);
        // For Asymmetric Keys include the PUB_KEY.
        if (keyType == ASYM_KEY_TYPE) {
          numParams = 6;
          Util.setShort(scratchPad, (short) 10, data[PUB_KEY]);
        }
        break;
      default:
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
     
    short authIndex = repository.alloc(MAX_AUTH_DATA_SIZE);
    short len = 0;
    Util.arrayFillNonAtomic(repository.getHeap(), authIndex, (short) MAX_AUTH_DATA_SIZE, (byte) 0);
    while (index < numParams) {
      short tag = Util.getShort(scratchPad, (short) (index * 2));
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
  
  private static short deriveKey(byte[] scratchPad) {
    // KeyDerivation:
    // 1. Do HMAC Sign, Auth data.
    // 2. HMAC Sign generates an output of 32 bytes length.
    // Consume only first 16 bytes as derived key.
    // Hmac sign.
    short len = seProvider.hmacKDF(
        seProvider.getMasterKey(),
        repository.getHeap(),
        data[AUTH_DATA],
        data[AUTH_DATA_LENGTH],
        scratchPad,
        (short) 0);
    if (len < 16) {
      KMException.throwIt(KMError.UNKNOWN_ERROR);
    }
    len = 16;
    data[DERIVED_KEY] = repository.alloc(len);
    // store the derived secret in data dictionary
    Util.arrayCopyNonAtomic(
        scratchPad, (short) 0, repository.getHeap(), data[DERIVED_KEY], len);
    return len;
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

  private static void sendResponse(APDU apdu, short err) {
    bufferProp[BUF_START_OFFSET] = repository.alloc((short) 5);
    short int32Ptr = buildErrorStatus(err);
    bufferProp[BUF_LEN_OFFSET] = encoder.encodeError(int32Ptr, (byte[]) bufferRef[0],
        bufferProp[BUF_START_OFFSET], (short) 5);
    sendOutgoing(apdu);
  }

  private short addIntegers(short authTime, short timeStamp, byte[] scratchPad) {
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 24, (byte) 0);
    Util.arrayCopyNonAtomic(
        KMInteger.cast(authTime).getBuffer(),
        KMInteger.cast(authTime).getStartOff(),
        scratchPad,
        (short) (8 - KMInteger.cast(timeStamp).length()),
        KMInteger.cast(timeStamp).length());

    // Copy timestamp to scratchpad
    Util.arrayCopyNonAtomic(
        KMInteger.cast(timeStamp).getBuffer(),
        KMInteger.cast(timeStamp).getStartOff(),
        scratchPad,
        (short) (16 - KMInteger.cast(timeStamp).length()),
        KMInteger.cast(timeStamp).length());

    // add authTime in millis to timestamp.
    KMUtils.add(scratchPad, (short) 0, (short) 8, (short) 16);
    return KMInteger.uint_64(scratchPad, (short) 16);
  }
  
  private void updateTrustedConfirmationOperation(KMOperationState op) {
    if (op.isTrustedConfirmationRequired()) {
      op.getTrustedConfirmationSigner().update(
          KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
          KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
          KMByteBlob.cast(data[INPUT_DATA]).length());
    }
  }
  
  private void finishTrustedConfirmationOperation(KMOperationState op) {
    // Perform trusted confirmation if required
    if (op.isTrustedConfirmationRequired()) {
      tmpVariables[0] =
          KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.CONFIRMATION_TOKEN, data[KEY_PARAMETERS]);
      if (tmpVariables[0] == KMType.INVALID_VALUE) {
        KMException.throwIt(KMError.NO_USER_CONFIRMATION);
      }
      tmpVariables[0] = KMByteTag.cast(tmpVariables[0]).getValue();
      boolean verified =
          op.getTrustedConfirmationSigner().verify(
              KMByteBlob.cast(data[INPUT_DATA]).getBuffer(),
              KMByteBlob.cast(data[INPUT_DATA]).getStartOff(),
              KMByteBlob.cast(data[INPUT_DATA]).length(),
              KMByteBlob.cast(tmpVariables[0]).getBuffer(),
              KMByteBlob.cast(tmpVariables[0]).getStartOff(),
              KMByteBlob.cast(tmpVariables[0]).length());
      if (!verified) {
        KMException.throwIt(KMError.NO_USER_CONFIRMATION);
      }
    }
  }
  
  private short createKeyBlobExp(short version) {
    short keyBlob = KMType.INVALID_VALUE;
    short byteBlobExp = KMByteBlob.exp();
    short keyChar = KMKeyCharacteristics.exp();
    short keyParam = KMKeyParameters.exp();
    switch(version) {
      case (short) 0:
        // Old KeyBlob has a maximum of 5 elements.
        keyBlob = KMArray.instance(ASYM_KEY_BLOB_SIZE_V0);
        KMArray.cast(keyBlob).add((short) 0, byteBlobExp);// Secret
        KMArray.cast(keyBlob).add((short) 1, byteBlobExp);// Nonce
        KMArray.cast(keyBlob).add((short) 2, byteBlobExp);// AuthTag
        KMArray.cast(keyBlob).add((short) 3, keyChar);// KeyChars
        KMArray.cast(keyBlob).add((short) 4, byteBlobExp);// PubKey
        break;
      case (short) 1:
        keyBlob = KMArray.instance(ASYM_KEY_BLOB_SIZE_V1);
        KMArray.cast(keyBlob).add(KEY_BLOB_VERSION_OFFSET, KMInteger.exp());// Version
        KMArray.cast(keyBlob).add(KEY_BLOB_SECRET, byteBlobExp);// Secret
        KMArray.cast(keyBlob).add(KEY_BLOB_NONCE, byteBlobExp);// Nonce
        KMArray.cast(keyBlob).add(KEY_BLOB_AUTH_TAG, byteBlobExp);// AuthTag
        KMArray.cast(keyBlob).add(KEY_BLOB_KEYCHAR, keyChar);// KeyChars
        KMArray.cast(keyBlob).add(KEY_BLOB_CUSTOM_TAGS, keyParam);// KeyChars
        KMArray.cast(keyBlob).add(KEY_BLOB_PUB_KEY, byteBlobExp);// PubKey
        break;
      default:
        KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    return keyBlob;
  }
  
  private static short createKeyBlobInstance(byte keyType) {
    short arrayLen = 0;
    switch (keyType) {
      case ASYM_KEY_TYPE:
        arrayLen = ASYM_KEY_BLOB_SIZE_V1;
        break;
      case SYM_KEY_TYPE:
        arrayLen = SYM_KEY_BLOB_SIZE_V1;
        break;
      default:
        KMException.throwIt(KMError.UNSUPPORTED_ALGORITHM);
    }
    return KMArray.instance(arrayLen);
  }
  
  private boolean isKeyUpgradeRequired(short keyBlob, short appId, short appData, byte[] scratchPad) {
    // Check if the KeyBlob is compatible. If there is any change in the KeyBlob, the version
    // Parameter in the KeyBlob should be updated to the next version.
    short version = readKeyBlobVersion(keyBlob);
    parseEncryptedKeyBlob(keyBlob, appId, appData, scratchPad, version);
    if (version < KEYBLOB_CURRENT_VERSION) {
      return true;
    }    
    short bootPatchLevel = repository.getBootPatchLevel();;
    // Fill the key-value properties in the scratchpad
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) 16, (byte) 0);
    Util.setShort(scratchPad, (short) 0, KMType.OS_VERSION);
    Util.setShort(scratchPad, (short) 2, repository.getOsVersion());
    Util.setShort(scratchPad, (short) 4, KMType.OS_PATCH_LEVEL);
    Util.setShort(scratchPad, (short) 6, repository.getOsPatch());
    Util.setShort(scratchPad, (short) 8, KMType.VENDOR_PATCH_LEVEL);
    Util.setShort(scratchPad, (short) 10, repository.getVendorPatchLevel());
    Util.setShort(scratchPad, (short) 12, KMType.BOOT_PATCH_LEVEL);
    Util.setShort(scratchPad, (short) 14, bootPatchLevel);
    short index = 0;
    short tag;
    short systemParam;
    boolean isKeyUpgradeRequired = false;
    while(index < 16) {
      tag = Util.getShort(scratchPad, index);
      systemParam = Util.getShort(scratchPad, (short) (index + 2));
      // validate the tag and check if key needs upgrade.
      short tagValue = KMKeyParameters.findTag(KMType.UINT_TAG, tag, data[HW_PARAMETERS]);
      tagValue = KMIntegerTag.cast(tagValue).getValue();
      short zero = KMInteger.uint_8((byte) 0);
      if (tagValue != KMType.INVALID_VALUE) {
        // OS version in key characteristics must be less the OS version stored in Javacard or the
        // stored version must be zero. Then only upgrade is allowed else it is invalid argument.
        if ((tag == KMType.OS_VERSION
            && KMInteger.compare(tagValue, systemParam) == 1
            && KMInteger.compare(systemParam, zero) == 0)) {
          // Key needs upgrade.
          isKeyUpgradeRequired = true;
        } else if ((KMInteger.compare(tagValue, systemParam) == -1)) {
          // Each os version or patch level associated with the key must be less than it's
          // corresponding value stored in Javacard, then only upgrade is allowed otherwise it
          // is invalid argument.
          isKeyUpgradeRequired = true;
        } else if (KMInteger.compare(tagValue, systemParam) == 1) {
          KMException.throwIt(KMError.INVALID_ARGUMENT);
        }
      } else {
        KMException.throwIt(KMError.UNKNOWN_ERROR);
      }
      index += 4;
    }
    return isKeyUpgradeRequired;
  }

  private short readKeyBlobVersion(short keyBlob) {
    short version = KMType.INVALID_VALUE;
    try {
      version = decoder.readKeyblobVersion(
          KMByteBlob.cast(keyBlob).getBuffer(),
          KMByteBlob.cast(keyBlob).getStartOff(),
          KMByteBlob.cast(keyBlob).length());
      if (version == KMType.INVALID_VALUE) {
        // If Version is not present. Then it is either an old KeyBlob or
        // corrupted KeyBlob.
        version = 0;
      } else {
        version = KMInteger.cast(version).getShort();
        if (version > KEYBLOB_CURRENT_VERSION || version < 0) {
          KMException.throwIt(KMError.INVALID_KEY_BLOB);
        }
      }
    } catch(Exception e) {
      KMException.throwIt(KMError.INVALID_KEY_BLOB);
    }
    return version;
  }
  
  private short getApplicationId(short params) {
    short appId = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_ID, params);
    if (appId != KMTag.INVALID_VALUE) {
      appId = KMByteTag.cast(appId).getValue();
      if (KMByteBlob.cast(appId).length() == 0) {
        // Treat empty as INVALID.
        return KMType.INVALID_VALUE;
      }
    }
    return appId;
  }

  private short getApplicationData(short params) {
    short appData = KMKeyParameters.findTag(KMType.BYTES_TAG, KMType.APPLICATION_DATA, params);
    if (appData != KMTag.INVALID_VALUE) {
      appData = KMByteTag.cast(appData).getValue();
      if (KMByteBlob.cast(appData).length() == 0) {
        // Treat empty as INVALID.
        return KMType.INVALID_VALUE;
      }
    }
    return appData;
  }
}
