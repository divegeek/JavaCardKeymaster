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

/**
 * This class provides data structure for information which is passed between the Keymaster Applet
 * and the commands. It is created by applet and initialized for the process request. Applet sets
 * repository, apdu and keymasterState. Command sets and uses incoming buffer information, outgoing
 * buffer information and operation state (if command is an operation).
 */
public class KMContext {
  private KMRepository repository;
  private byte keymasterState;
  private KMOperationState opState;
  private byte[] buffer;
  private short bufferLength;
  /**
   * Setter for the keymasterState. Set by the applet.
   *
   * @param keymasterState represents current applet state.
   */
  public void setKeymasterState(byte keymasterState) {
    this.keymasterState = keymasterState;
  }

  /**
   * Getter for keymasterState. Used by the commands.
   *
   * @return keymasterState represents current applets state.
   */
  public byte getKeymasterState() {
    return keymasterState;
  }


  /**
   * Getter for buffer used for receiving or sending data to or from the master. Used by the
   * messenger.
   *
   * @return buffer which is used to copying data to and from apdu's buffer. Start offset is always
   *     0.
   */
  public byte[] getBuffer() {
    return buffer;
  }

  /**
   * Setter for buffer. Used by the repository.
   *
   * @param buffer which is used to copying data to and from apdu's buffer.
   */
  public void setBuffer(byte[] buffer) {
    this.buffer = buffer;
  }

  /**
   * Getter for buffer length. Used by the messenger and commands.
   *
   * @return buffer length.
   */
  public short getBufferLength() {
    return bufferLength;
  }

  /**
   * Setter for buffer length. Used by the messenger commands.
   *
   * @param length of buffer.
   */
  public void setBufferLength(short length) {
    this.bufferLength = length;
  }

  /**
   * Getter for repository instance. Used by commands.
   *
   * @return repository
   */
  public KMRepository getRepository() {
    return repository;
  }

  /**
   * Setter for the repository instance. Used by the applet.
   *
   * @param repository is repository of the KMType objects and other objects.
   */
  public void setRepository(KMRepository repository) {
    this.repository = repository;
  }

  /**
   * Getter for the OperationState for operation specific commands. Used by commands.
   *
   * @return Operation state associated with the command.
   */
  public KMOperationState getOpState() {
    return opState;
  }

  /** Setter for the OperationState for operation specific commands. Used by commands. */
  public void setOpState(KMOperationState opState) {
    this.opState = opState;
  }
}
