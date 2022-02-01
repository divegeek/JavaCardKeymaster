package com.android.javacard.jcproxy;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.android.javacard.keymaster.KMJCardSimApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;

import javacard.framework.AID;

public class JCardSimulator implements Simulator {

  private CardSimulator simulator;
  ResponseAPDU response;

  public JCardSimulator() {
    simulator = new CardSimulator();
  }

  @Override
  public void initaliseSimulator() throws Exception {
  }

  @Override
  public void disconnectSimulator() throws Exception {
    AID appletAID1 = AIDUtil.create("A000000062");
    // Delete i.e. uninstall applet
    simulator.deleteApplet(appletAID1);
  }

  @Override
  public boolean setupKeymasterOnSimulator(byte applicationSpecificParam) throws Exception {
    AID appletAID1 = AIDUtil.create("A000000062");
    byte[] data = new byte[2];
    data[0] = 0x01; // length
    data[1] = applicationSpecificParam;
    simulator.installApplet(appletAID1, KMJCardSimApplet.class, data, (short) 0, (byte) data.length);
    // Select applet
    simulator.selectApplet(appletAID1);
    return true;
  }

  private final byte[] intToByteArray(int value) {
    return new byte[] {
            (byte) (value >>> 8), (byte) value };
  }

  @Override
  public byte[] executeApdu(byte[] apdu) throws Exception {
    System.out.println("Executing APDU = " + Utils.byteArrayToHexString(apdu));
    CommandAPDU apduCmd = new CommandAPDU(apdu);
    response = simulator.transmitCommand(apduCmd);
    System.out.println("Status = "
            + Utils.byteArrayToHexString(intToByteArray(response.getSW())));
    return intToByteArray(response.getSW());
  }

  @Override
  public byte[] decodeDataOut() {
    return response.getData();
  }

}
