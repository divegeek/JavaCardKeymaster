# Provisioning tool
This directory contains two tools. One which constructs the apdus and dumps them to a json file, Other which gets the apuds from the json file and provision them into a secure element simulator. Both the tools can be compiled and executed from a Linux machine.

#### Build instruction
The default target generates both the executables. One construct_apdus and the other provision.
$ make
Individual targets can also be selected as shown below
$ make construct_apdus
$ make provision
Make clean will remove all the object files and binaries
$ make clean

#### Environment setup
Before executing the binaries make sure LD_LIBRARY_PATH is set
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH

#### Sample resources for quick testing
Two sample json files are located in this directory with names
[sample_json_cf.txt](sample_json_cf.txt) and and [sample_json_gf.txt](sample_json_gf.txt)
for your reference. Use sample_json_cf.txt for cuttlefish target and use
sample_json_gf.txt for goldfish target. Also the required certificates and
keys can be found in [test_resources](test_resources) directory. Copy the
certificates and the key into the emulator/device filesystem in their respective
paths mentioned in the sample json file.

#### Usage for construct_apdus
<pre>
Usage: construct_apdus options
Valid options are:
-h, --help                        show the help message and exit.
-v, --km_version version Version of the keymaster (40 or 41 for respective keymaster version; 100 for keymint)
-i, --input  jsonFile	 Input json file
-o, --output jsonFile 	 Output json file
</pre>

#### Usage for provision
<pre>
Usage: provision options
Valid options are:
-h, --help                      show the help message and exit.
-v, --km_version version  Version of the keymaster (40 or 41 for respective keymaster versions; 100 for keymint)
-i, --input  jsonFile 	  Input json file 
-s, --provision_stautus   Prints the current provision status.
-l, --lock_provision      Locks the provision state.
</pre>
