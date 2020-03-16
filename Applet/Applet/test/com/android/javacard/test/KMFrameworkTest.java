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

package com.android.javacard.test;

import com.android.javacard.keymaster.KMArray;
import com.android.javacard.keymaster.KMByteBlob;
import com.android.javacard.keymaster.KMDecoder;
import com.android.javacard.keymaster.KMEncoder;
import com.android.javacard.keymaster.KMEnum;
import com.android.javacard.keymaster.KMEnumTag;
import com.android.javacard.keymaster.KMKeyParameters;
import com.android.javacard.keymaster.KMKeymasterApplet;
import com.android.javacard.keymaster.KMType;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.theories.suppliers.TestedOn;

public class KMFrameworkTest {

  @Test
  public void test_Lifecycle_Success() {
    // Create simulator
    CardSimulator simulator = new CardSimulator();

    // Install applet
    AID appletAID1 = AIDUtil.create("A000000062");
    simulator.installApplet(appletAID1, KMKeymasterApplet.class);

    // Select applet
    simulator.selectApplet(appletAID1);
    testProvisionCmd(simulator);
    testGetHwInfoCmd(simulator);
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID1);
  }

  public void testProvisionCmd(CardSimulator simulator){
      byte[] buf = new byte[512];
      // test provision command
      KMArray cmd = makeProvisionCmd();
      KMEncoder enc = new KMEncoder();
      short actualLen = enc.encode(cmd, buf, (short) 0, (short)buf.length);
      CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x23, 0x40, 0x00, buf, 0, actualLen);
      //print(commandAPDU.getBytes());;
      ResponseAPDU response = simulator.transmitCommand(commandAPDU);
      Assert.assertEquals(0x9000, response.getSW());
  }

  public void testGetHwInfoCmd(CardSimulator simulator){
    byte[] buf = new byte[512];
    CommandAPDU commandAPDU = new CommandAPDU(0x80, 0x1E, 0x40, 0x00);
    //print(commandAPDU.getBytes());
    ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    KMDecoder dec = new KMDecoder();
    KMArray exp = KMArray.instance((short)3)
      .add((short)0, KMEnum.instance().setType(KMType.HARDWARE_TYPE))
      .add((short)1, KMByteBlob.instance())
      .add((short)2, KMByteBlob.instance());
    byte[] respBuf = response.getBytes();
    short len = (short)respBuf.length;
    KMArray resp = dec.decode(exp,respBuf, (short)0, len);
    Assert.assertEquals(3, resp.length());
    KMEnum secLevel = (KMEnum)resp.get((short)0);
    KMByteBlob kmName = (KMByteBlob) resp.get((short)1);
    KMByteBlob authorName = (KMByteBlob) resp.get((short)2);
    Assert.assertEquals(KMType.HARDWARE_TYPE, secLevel.getType());
    Assert.assertEquals(KMType.STRONGBOX, secLevel.getVal());
    String kmNameStr = byteBlobToString(kmName);
    String authorNameStr = byteBlobToString(authorName);
    Assert.assertEquals( "JavacardKeymasterDevice",kmNameStr);
    Assert.assertEquals( "Google",authorNameStr);
    Assert.assertEquals(0x9000, response.getSW());
  }

  private String byteBlobToString(KMByteBlob blob) {
    StringBuilder sb = new StringBuilder();
    for(short i = 0; i<blob.length(); i++){
      sb.append((char)blob.get(i));
    }
    return sb.toString();
  }

  private void print(byte[] cmdApdu){
    StringBuilder sb = new StringBuilder();
    for(int i = 0; i < cmdApdu.length; i++){
      sb.append(String.format(" 0x%02X", cmdApdu[i])) ;
      if(((i-1)%38 == 0) && ((i-1) >0)){
        sb.append(";\n");
      }
    }
    System.out.println(sb.toString());
  }

  private KMArray makeProvisionCmd() {
    // Argument 1
    KMArray vals =
        KMArray.instance((short) 1)
            .add((short) 0, KMEnumTag.instance(KMType.ALGORITHM, KMType.RSA));
    KMKeyParameters keyparams = KMKeyParameters.instance(vals);
    // Argument 2
    KMEnum keyFormat = KMEnum.instance(KMType.KEY_FORMAT, KMType.X509);
    // Argument 3
    byte[] byteBlob = new byte[48];
    for (short i = 0; i < 48; i++) {
      byteBlob[i] = (byte) i;
    }
    KMByteBlob keyBlob = KMByteBlob.instance(byteBlob, (short) 0, (short)byteBlob.length);
    // Array of expected arguments
    return KMArray.instance((short) 3)
        .add((short) 0, keyparams)
        .add((short) 1, keyFormat)
        .add((short) 2, keyBlob);
  }
}
