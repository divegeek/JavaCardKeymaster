/*
 **
 ** Copyright 2021, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */
#pragma once

class SocketTransport
{
public:
   static inline std::shared_ptr<SocketTransport> getInstance() {
       static std::shared_ptr<SocketTransport> socket = std::shared_ptr<SocketTransport>(new SocketTransport());
       return socket;
   }

  ~SocketTransport();
  /**
     * Creates a socket instance and connects to the provided server IP and port.
     */
  bool openConnection();
  /**
     * Sends data over socket and receives data back.
     */
  bool sendData(const std::vector<uint8_t> &inData, std::vector<uint8_t> &output);
  /**
     * Closes the connection.
     */
  bool closeConnection();
  /**
     * Returns the state of the connection status. Returns true if the connection is active,
     * false if connection is broken.
     */
  bool isConnected();

private:
  bool readData(std::vector<uint8_t>& output);
  SocketTransport() : mSocket(-1), socketStatus(false) {}
  /**
     * Socket instance.
     */
  int mSocket;
  bool socketStatus;
};
