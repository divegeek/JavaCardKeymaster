# JavaCardKeymaster Applet

This directory contains the implementation of the Keymint 1.0
interface, in the form of a JavaCard 3.0.5 applet which runs in a secure
element.  It must be deployed in conjuction with the associated HAL,
which mediates between Android Keystore and this applet.

# Supported Features!

  - Keymint 1.0 supported functions for required VTS compliance.
  - SharedSecret 1.0 supported functions for required VTS compliance.

# Not supported features
  - Factory provisioned attestation key will not be supported in this applet.
  - Limited usage keys will not be supported in this applet.
