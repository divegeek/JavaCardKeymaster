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
  public static final short MAX_LENGTH = (short) 0x04ff; // TODO: make this value configurable.
  private static final byte CLA_ISO7816_NO_SM_NO_CHAN = (byte) 0x80;
  private static final byte KM_HAL_VERSION = (byte) 0x41;

  // Possible states of the applet.
  public static final byte ILLEGAL_STATE = 0x00;
  public static final byte INSTALL_STATE = 0x01;
  public static final byte FIRST_SELECT_STATE = 0x02;
  public static final byte ACTIVE_STATE = 0x03;
  public static final byte INACTIVE_STATE = 0x04;
  public static final byte UNINSTALLED_STATE = 0x05;

  // State of the applet.
  private byte keymasterState = ILLEGAL_STATE;
  private KMRepository repository;

  /**
   * Registers this applet.
   *
   * @param repo reference to the repository which manages all the NVM objects.
   */
  protected KMKeymasterApplet(KMRepository repo) {
    repository = repo;
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
    KMRepository repo = new KMRepository();
    // TODO: Read the configuration from the package and pass the data in initialize method.
    repo.initialize();
    KMKeymasterApplet keymaster = new KMKeymasterApplet(repo);
    keymaster.setKeymasterState(KMKeymasterApplet.INSTALL_STATE);
  }

  /**
   * Selects this applet.
   *
   * @return Returns true if the keymaster is in correct state
   */
  @Override
  public boolean select() {
    repository.onSelect();
    if (getKeymasterState() == KMKeymasterApplet.INSTALL_STATE) {
      setKeymasterState(KMKeymasterApplet.FIRST_SELECT_STATE);
    } else if (getKeymasterState() == KMKeymasterApplet.INACTIVE_STATE) {
      setKeymasterState(KMKeymasterApplet.ACTIVE_STATE);
    } else {
      return false;
    }
    return true;
  }

  /** De-selects this applet. */
  @Override
  public void deselect() {
    repository.onDeselect();
    if (getKeymasterState() == KMKeymasterApplet.ACTIVE_STATE) {
      setKeymasterState(KMKeymasterApplet.INACTIVE_STATE);
    }
  }

  /** Uninstalls the applet after cleaning the repository. */
  @Override
  public void uninstall() {
    repository.onUninstall();
    if (getKeymasterState() != KMKeymasterApplet.UNINSTALLED_STATE) {
      setKeymasterState(KMKeymasterApplet.UNINSTALLED_STATE);
    }
  }

  /**
   * Processes an incoming APDU and handles it using command objects.
   *
   * @see APDU
   * @param apdu the incoming APDU
   */
  @Override
  public void process(APDU apdu) {
    repository.onProcess();
    // Verify whether applet is in correct state.
    if ((getKeymasterState() != KMKeymasterApplet.ACTIVE_STATE)
        && (getKeymasterState() != KMKeymasterApplet.FIRST_SELECT_STATE)) {
      throw new KMException(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
    }
    // If this is select applet apdu which is selecting this applet then return
    if (apdu.isISOInterindustryCLA()) {
      if (selectingApplet()) {
        return;
      }
    }

    // Read the apdu header and buffer.
    byte[] buffer = apdu.getBuffer();
    byte apduClass = buffer[ISO7816.OFFSET_CLA];
    byte apduIns = buffer[ISO7816.OFFSET_INS];
    byte halVersion = buffer[ISO7816.OFFSET_P1];
    byte apduP2 = buffer[ISO7816.OFFSET_P2];

    // Validate APDU Header.
    if ((apduClass != CLA_ISO7816_NO_SM_NO_CHAN)) {
      throw new KMException(ISO7816.SW_CLA_NOT_SUPPORTED);
    } else if ((halVersion != KMKeymasterApplet.KM_HAL_VERSION) && (apduP2 != (byte) 0x00)) {
      throw new KMException(ISO7816.SW_INCORRECT_P1P2);
    }

    // Process the APDU.
    try {
      // Get the command object for specific INS from the repository.
      KMCommand command = repository.getCommand(apduIns);
      // Get the empty context object from the repository.
      KMContext context = repository.getContext();
      // Initialize context
      context.setKeymasterState(getKeymasterState());
      context.setBuffer(repository.getBuffer());
      if(command.hasArguments()){
        receiveIncoming(context, apdu);
      }
      // Execute the command. If the execution fails then an exception is thrown.
      command.execute(context);

      // context has data that needs to be sent
      if(context.getBufferLength() >0 ){
        sendOutgoing(context, apdu);
      }

      // Update the Keymaster state according to the context.
      setKeymasterState(context.getKeymasterState());
    } catch (KMException exception) {
      // TODO: error handling for command related error.
      // TODO: This should result in ISOException or exception with keymaster specific error codes
    }
  }

  /**
   * Sends a response, may be extended response, as requested by the command.
   *
   * @param context of current command.
   */
  public void sendOutgoing(KMContext context, APDU apdu) {
    // Initialize source
    short srcLength = context.getBufferLength();
    if (srcLength > MAX_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    // Send data
    byte[] srcBuffer = context.getBuffer();
    apdu.setOutgoing();
    apdu.setOutgoingLength(srcLength);
    apdu.sendBytesLong(srcBuffer, (short) 0, srcLength);
  }

  /**
   * Receives data, which can be extended data, as requested by the command instance.
   *
   * @param context of current command.
   */
  public void receiveIncoming(KMContext context, APDU apdu) {
    // Initialize source
    byte[] srcBuffer = apdu.getBuffer();
    // Initialize destination
    byte[] destBuffer = context.getBuffer();
    short destOffset = (short) 0;

    // Receive data
    short recvLen = apdu.setIncomingAndReceive();
    short srcOffset = apdu.getOffsetCdata();
    short srcLength = apdu.getIncomingLength();
    if (srcLength > MAX_LENGTH) {
      throw new KMException(ISO7816.SW_WRONG_LENGTH);
    }
    while (recvLen > 0) {
      Util.arrayCopyNonAtomic(srcBuffer, srcOffset, destBuffer, destOffset, recvLen);
      destOffset += recvLen;
      recvLen = apdu.receiveBytes(srcOffset);
    }
    // Update the Context
    context.setBufferLength(srcLength);
  }

  /**
   * Getter for keymaster state.
   *
   * @return keymasterState - current state of the applet.
   */
  private byte getKeymasterState() {
    return keymasterState;
  }
  /** Setter for keymaster state. */
  private void setKeymasterState(byte keymasterState) {
    this.keymasterState = keymasterState;
  }
}
