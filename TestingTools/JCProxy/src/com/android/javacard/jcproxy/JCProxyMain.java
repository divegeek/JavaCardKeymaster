package com.android.javacard.jcproxy;

import java.io.*;
import java.net.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import com.sun.javacard.apduio.CadTransportException;

/**
 * This program demonstrates a simple TCP/IP socket server.
 *
 * @author www.codejava.net
 */
public class JCProxyMain {

  public static void main(String[] args) {
    if (args.length < 1) {
      System.out.println("Port no is expected as argument.");
      return;
    }

    int port = Integer.parseInt(args[0]);
    Simulator simulator = new JCardSimulator();

    try (ServerSocket serverSocket = new ServerSocket(port)) {
      simulator.initaliseSimulator();
      if (!simulator.setupKeymasterOnSimulator()) {
        System.out.println("Failed to setup Java card keymaster simulator.");
        System.exit(-1);
      }
      byte[] outData;

      while (true) {
        try {
          Socket socket = serverSocket.accept();
          System.out.println("\n\n\n\n\n");
          System.out.println("------------------------New client connected on "
                  + socket.getPort() + "--------------------");
          OutputStream output = null;
          InputStream isReader = null;
          try {
            socket.setReceiveBufferSize(1024 * 5);
            output = socket.getOutputStream();
            isReader = socket.getInputStream();

            byte[] inBytes = new byte[65536];
            int readLen = 0, index = 0;
            System.out.println("Socket input buffer size: "
                    + socket.getReceiveBufferSize());
            while ((readLen = isReader.read(inBytes, index, 1024 * 5)) > 0) {
              if (readLen > 0) {
                System.out.println("Bytes read from index (" + index
                        + ") socket: " + readLen + " Estimate read: "
                        + isReader.available());
                byte[] outBytes;

                try {
                  outBytes = simulator.executeApdu(
                          Arrays.copyOfRange(inBytes, 0, index + readLen));
                  outData = simulator.decodeDataOut();
                  System.out.println(
                          "Return Data " + Utils.byteArrayToHexString(outData));
                  byte[] finalOutData = new byte[outData.length
                          + outBytes.length];
                  System.arraycopy(outData, 0, finalOutData, 0, outData.length);
                  System.arraycopy(outBytes, 0, finalOutData, outData.length,
                          outBytes.length);
                  output.write(finalOutData);
                  output.flush();
                  index = 0;
                } catch (IllegalArgumentException e) {
                  e.printStackTrace();
                  index = readLen;
                }
              }
            }
          } catch (IOException e) {
            e.printStackTrace();
          } catch (Exception e) {
            e.printStackTrace();
          } finally {
            if (output != null)
              output.close();
            if (isReader != null)
              isReader.close();
            socket.close();
          }
        } catch (IOException e) {
          break;
        } catch (Exception e) {
          break;
        }
        System.out.println("Client disconnected.");
      }
      simulator.disconnectSimulator();
    } catch (IOException ex) {
      System.out.println("Server exception: " + ex.getMessage());
      ex.printStackTrace();
    } catch (CadTransportException e1) {
      e1.printStackTrace();
    } catch (Exception e1) {
      e1.printStackTrace();
    }
  }
}
