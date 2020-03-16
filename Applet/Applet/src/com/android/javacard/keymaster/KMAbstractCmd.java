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

public abstract class KMAbstractCmd implements KMCommand {

  /**
   * Implements the KMCommand interface.
   *
   * @param context provides information required to execute the command.
   */
  @Override
  public void execute(KMContext context) {
    // Assert the command's operational state
    if (!this.validateState(context.getKeymasterState())) {
      throw new KMException(KMException.CMD_NOT_ACCEPTED_WRONG_STATE);
    }
    KMEncoder encoder = context.getRepository().getEncoder();
    KMDecoder decoder = context.getRepository().getDecoder();
    // Get getExpectedArgs if expected
    KMArray args = null;
    if (hasArguments()) {
      // Deserialize the getExpectedArgs
      KMArray argsProto = getExpectedArgs();
      args = decoder.decode(argsProto, context.getBuffer(), (short) 0, context.getBufferLength());
    }
    // Pass control to concrete command subclass
    KMArray resp = this.process(args, context);
    context.setBufferLength((short)0);
    // If there is resp then serialize and send
    if (resp != null) {
      // set outgoing buffer
      short len = encoder.encode(resp, context.getBuffer(), (short) 0, (short)context.getBuffer().length);
      context.setBufferLength(len);
    }
  }

  /**
   * Get the getExpectedArgs prototype expression from the concrete subclass.
   *
   * @return KMArray of KMType objects which provides expression for the command's getExpectedArgs..
   */
  protected abstract KMArray getExpectedArgs();

  /**
   * Implemented by the subclass to execute the command specific functionality.
   *
   * @param args which are decoded from the the apdu.
   * @param context within which the command should be executed.
   * @return Null or response having the result of the command's execution.
   */
  protected abstract KMArray process(KMArray args, KMContext context);

  /**
   * Validate the state required by the command to execute. By default all the commands can execute
   * in active state.
   *
   * @param state is the current state of the applet
   * @return true if the state is valid for command's execution else false is returned.
   */
  protected boolean validateState(byte state) {
    return (KMKeymasterApplet.ACTIVE_STATE == state);
  }

  @Override
  public boolean hasArguments(){
    return true;
  }
}
