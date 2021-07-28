# JavaCardKeymaster Applet

This directory contains the implementation of the Keymaster 4.1
interface, in the form of a JavaCard 3.0.5 applet which runs in a secure
element.  It must be deployed in conjuction with the associated HAL,
which serves to intermediate between Android Keystore and this applet.

# Supported Features!

  - Support for AndroidSEProvider, which is compliant to JavaCard platform, Classic Edition 3.0.5.
  - Keymaster 4.1 supported functions for required VTS compliance.
  - Support for SE Provisioning and bootup
  - Support for Global platoform Amendment H in AndroidSEProvider.
  - Unit test using JCardSim.

#### Building for source
- Install Javacard 3.0.5 classic sdk.
- set JC_HOME_SIMULATOR environment variable to the installed sdk.
- Give ant build from Applet folder.
