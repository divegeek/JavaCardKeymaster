# TestingTools
[JCProxy](JCProxy) is a testing tool, which provides a way to communicate with 
JCardSimulator from android emulator/device.
It basically opens a socket connection on the port (port mentioned in program arguments)
and listens for the incomming data on this port. This tool uses apduio and JCarsim jars
to validate and transmit the APDUs to the Keymaster Applet.
