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
import javacard.framework.CardRuntimeException;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacardx.apdu.ExtendedLength;

/**
 * KMKeymasterApplet implements the javacard applet. It creates repository and other install time
 * objects. It also implements the keymaster state machine and handles javacard applet life cycle
 * events.
 */
// TODO Currently implementing ExtendedLength for ease of testing
//  - remove this in future.
public class KMKeymasterApplet extends Applet implements AppletEvent, ExtendedLength {
  // Constants.
  private static final short MAX_LENGTH = (short) 0x1000; // TODO: make this value configurable.
  private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  private static final short KM_HAL_VERSION = (short) 0x4000;

  // Possible states of the applet.
  private static final byte ILLEGAL_STATE = 0x00;
  private static final byte INSTALL_STATE = 0x01;
  private static final byte FIRST_SELECT_STATE = 0x02;
  private static final byte ACTIVE_STATE = 0x03;
  private static final byte INACTIVE_STATE = 0x04;
  private static final byte UNINSTALLED_STATE = 0x05;

  // Commands
  private static final byte INS_GENERATE_KEY_CMD = 0x10;
  private static final byte INS_IMPORT_KEY_CMD = 0x11;
  private static final byte INS_IMPORT_WRAPPED_KEY_CMD = 0x12;
  private static final byte INS_EXPORT_KEY_CMD = 0x13;
  private static final byte INS_ATTEST_KEY_CMD = 0x14;
  private static final byte INS_UPGRADE_KEY_CMD = 0x15;
  private static final byte INS_DELETE_KEY_CMD = 0x16;
  private static final byte INS_DELETE_ALL_KEYS_CMD = 0x17;
  private static final byte INS_ADD_RNG_ENTROPY_CMD = 0x18;
  private static final byte INS_COMPUTE_SHARED_HMAC_CMD = 0x19;
  private static final byte INS_DESTROY_ATT_IDS_CMD = 0x1A;
  private static final byte INS_VERIFY_AUTHORIZATION_CMD = 0x1B;
  private static final byte INS_GET_HMAC_SHARING_PARAM_CMD = 0x1C;
  private static final byte INS_GET_KEY_CHARACTERISTICS_CMD = 0x1D;
  private static final byte INS_GET_HW_INFO_CMD = 0x1E;
  private static final byte INS_BEGIN_OPERATION_CMD = 0x1F;
  private static final byte INS_UPDATE_OPERATION_CMD = 0x20;
  private static final byte INS_FINISH_OPERATION_CMD = 0x21;
  private static final byte INS_ABORT_OPERATION_CMD = 0x22;
  private static final byte INS_PROVISION_CMD = 0x23;

  // GetHwInfo information
  // TODO change this to just filling the buffer
  private static final short MAX_SEED_SIZE = 2048;

  // State of the applet.
  private KMEncoder encoder;
  private KMDecoder decoder;
  private KMRepository repository;
  private byte keymasterState = ILLEGAL_STATE;
  private byte[] buffer;
  private short bufferStartOffset;
  private short bufferLength;

  /** Registers this applet. */
  protected KMKeymasterApplet() {
    keymasterState = KMKeymasterApplet.INSTALL_STATE;
    repository = KMRepository.instance();
    KMUtil.init();
    KMType.initialize();
    encoder = new KMEncoder();
    decoder = new KMDecoder();
    register();
  }

  /**
   * Installs this applet.
   *
   * @param bArray the array containing installation parameters
   * @param bOffset the starting offset in bArray
   * @param bLength the length in bytes of the parameter data in bArray
   */
  public static void install(byte[] bArray, short bOffset, byte bLength) {
    KMKeymasterApplet keymaster = new KMKeymasterApplet();
  }

  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
    repository.onSelect();
    if (keymasterState == KMKeymasterApplet.INSTALL_STATE) {
      keymasterState = KMKeymasterApplet.FIRST_SELECT_STATE;
    } else if (keymasterState == KMKeymasterApplet.INACTIVE_STATE) {
      keymasterState = KMKeymasterApplet.ACTIVE_STATE;
    } else {
      return false;
    }
    return true;
  }

  /** De-selects this applet. */
  @Override
  public void deselect() {
    repository.onDeselect();
    if (keymasterState == KMKeymasterApplet.ACTIVE_STATE) {
      keymasterState = KMKeymasterApplet.INACTIVE_STATE;
    }
  }

  /** Uninstalls the applet after cleaning the repository. */
  @Override
  public void uninstall() {
    repository.onUninstall();
    if (keymasterState != KMKeymasterApplet.UNINSTALLED_STATE) {
      keymasterState = KMKeymasterApplet.UNINSTALLED_STATE;
    }
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   *
   * @param apdu the incoming APDU
   */
  @Override
  public void process(APDU apdu) {
    repository.onProcess();
    // Verify whether applet is in correct state.
    if ((keymasterState != KMKeymasterApplet.ACTIVE_STATE)
        && (keymasterState != KMKeymasterApplet.FIRST_SELECT_STATE)) {
      ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // If this is select applet apdu which is selecting this applet then return
    if (apdu.isISOInterindustryCLA()) {
      if (selectingApplet()) {
        return;
      }
    }
    // Read the apdu header and buffer.
    byte[] apduBuffer = apdu.getBuffer();
    byte apduClass = apduBuffer[ISO7816.OFFSET_CLA];
    byte apduIns = apduBuffer[ISO7816.OFFSET_INS];
    short P1P2 = Util.getShort(apduBuffer, ISO7816.OFFSET_P1);
    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
    } else if (P1P2 != KMKeymasterApplet.KM_HAL_VERSION) {
      ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
    }
    // Validate whether INS can be supported
    if (!(apduIns >= INS_GENERATE_KEY_CMD && apduIns <= INS_PROVISION_CMD)) {
      ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
    // Validate if INS is provision command if applet is in FIRST_SELECT_STATE.
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      if (apduIns != INS_PROVISION_CMD) {
        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
      }
    }
    // Process the apdu
    try {
      // Handle the command
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
          processVerifyAuthenticationCmd(apdu);
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
        case INS_PROVISION_CMD:
          processProvisionCmd(apdu);
          break;
        default:
          ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
      }

    } catch (CardRuntimeException exception) {
      if (!(KMException.handle(exception.getReason()))) {
        CardRuntimeException.throwIt(exception.getReason());
      }
    } finally {
      repository.clean();
    }
  }

  /** Sends a response, may be extended response, as requested by the command. */
  private void sendOutgoing(APDU apdu) {
    if (bufferLength > MAX_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    apdu.setOutgoing();
    apdu.setOutgoingLength(bufferLength);
    apdu.sendBytesLong(buffer, bufferStartOffset, bufferLength);
  }

  /** Receives data, which can be extended data, as requested by the command instance. */
  private void receiveIncoming(APDU apdu) {
    byte[] srcBuffer = apdu.getBuffer();
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    bufferLength  = apdu.getIncomingLength();
    bufferStartOffset = repository.alloc(bufferLength);
    buffer = repository.getHeap();
    short index = bufferStartOffset;
    // Receive data
    if (bufferLength > MAX_LENGTH) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    while (recvLen > 0 && ((short)(index - bufferStartOffset) < bufferLength)) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, buffer, index, recvLen);
      index += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
  }

  private void processProvisionCmd(APDU apdu) {
    // Receive the incoming request fully from the master into buffer.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Argument 1
    short keyparams = KMKeyParameters.exp();
    // Argument 2
    short keyFormat = KMEnum.instance(KMType.KEY_FORMAT);
    // Argument 3
    short keyBlob = KMByteBlob.exp();
    // Array of expected arguments
    short argsProto = KMArray.instance((short) 3);
    KMArray.cast(argsProto).add((short) 0, keyparams);
    KMArray.cast(argsProto).add((short) 1, keyFormat);
    KMArray.cast(argsProto).add((short) 2, keyBlob);
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // TODO execute the function
    // Change the state to ACTIVE
    if (keymasterState == KMKeymasterApplet.FIRST_SELECT_STATE) {
      keymasterState = KMKeymasterApplet.ACTIVE_STATE;
    }
  }

  private void processGetHwInfoCmd(APDU apdu) {
    // No arguments expected
    final byte[] JavacardKeymasterDevice = {
      0x4A, 0x61, 0x76, 0x61, 0x63, 0x61, 0x72, 0x64, 0x4B, 0x65, 0x79, 0x6D, 0x61, 0x73, 0x74, 0x65,
      0x72, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,
    };
    final byte[] Google = {0x47, 0x6F, 0x6F, 0x67, 0x6C, 0x65};

    // Make the response
    short respPtr = KMArray.instance((short) 3);
    KMArray resp = KMArray.cast(respPtr);
    resp.add((short) 0, KMEnum.instance(KMType.HARDWARE_TYPE, KMType.STRONGBOX));
    resp.add((short) 1, KMByteBlob.instance(
                    JavacardKeymasterDevice, (short) 0, (short) JavacardKeymasterDevice.length));
    resp.add((short) 2, KMByteBlob.instance(Google, (short) 0, (short) Google.length));
    //TODO change from MAX_LENGTH to actual length.
    buffer = repository.getHeap();
    bufferStartOffset = repository.alloc((short)128);
    // Encode the response - actual bufferLength is 86
    bufferLength = encoder.encode(respPtr, buffer, bufferStartOffset, MAX_LENGTH);
    // send buffer to master
    sendOutgoing(apdu);
  }

  private void processAddRngEntropyCmd(APDU apdu) {
    // Receive the incoming request fully from the master.
    receiveIncoming(apdu);
    // Re-purpose the apdu buffer as scratch pad.
    byte[] scratchPad = apdu.getBuffer();
    Util.arrayFillNonAtomic(scratchPad, (short) 0, (short) apdu.getBuffer().length, (byte) 0);
    // Argument 1
    short argsProto = KMArray.instance((short) 1);
    KMArray.cast(argsProto).add((short) 0, KMByteBlob.exp());
    // Decode the argument
    short args = decoder.decode(argsProto, buffer, bufferStartOffset, bufferLength);
    // Process
    KMByteBlob blob = KMByteBlob.cast(KMArray.cast(args).get((short) 0));
    // Maximum 2KiB of seed is allowed.
    if (blob.length() > MAX_SEED_SIZE) {
      ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }
    // Get existing entropy pool.
    byte[] entPool = KMUtil.getEntropyPool();
    // Create new temporary pool.
    byte[] heapRef = repository.getHeap();
    short poolStart = repository.alloc((short) entPool.length);
    // Populate the new pool with the entropy which is derived from current entropy pool.
    KMUtil.newRandomNumber(heapRef, poolStart, (short) entPool.length);
    // Copy the entropy to the current pool - updates the entropy pool.
    Util.arrayCopy(heapRef, poolStart, entPool, (short) 0, (short) entPool.length);
    short index = 0;
    short randIndex = 0;
    // Mix (XOR) the seed received from the master in the entropy pool - 32 bytes (entPool.length).
    // at a time.
    while (index < blob.length()) {
      entPool[randIndex] = (byte) (entPool[randIndex] ^ blob.get(index));
      randIndex++;
      index++;
      if (randIndex >= entPool.length) {
        randIndex = 0;
      }
    }
  }

  private void processAbortOperationCmd(APDU apdu) {

  }

  private  void processFinishOperationCmd(APDU apdu) {

  }

  private  void processUpdateOperationCmd(APDU apdu) {

  }

  private  void processBeginOperationCmd(APDU apdu) {

  }

  private  void processGetKeyCharacteristicsCmd(APDU apdu) {

  }

  private  void processGetHmacSharingParamCmd(APDU apdu) {

  }

  private  void processVerifyAuthenticationCmd(APDU apdu) {

  }

  private  void processDestroyAttIdsCmd(APDU apdu) {

  }

  private  void processComputeSharedHmacCmd(APDU apdu) {

  }

  private  void processDeleteAllKeysCmd(APDU apdu) {

  }

  private  void processDeleteKeyCmd(APDU apdu) {

  }

  private  void processUpgradeKeyCmd(APDU apdu) {

  }

  private  void processAttestKeyCmd(APDU apdu) {

  }

  private  void processExportKeyCmd(APDU apdu) {

  }

  private  void processImportWrappedKeyCmd(APDU apdu) {

  }

  private  void processImportKeyCmd(APDU apdu) {

  }

  private  void processGenerateKey(APDU apdu) {

  }
}
