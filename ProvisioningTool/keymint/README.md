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
one sample json files is located in this directory with name
[sample_json_keymint_cf.txt](sample_json_keymint_cf.txt)
for your reference. Use sample_json_keymint_cf.txt for keymint
cuttlefish target. Also the required certificates and keys can be found in 
[test_resources](test_resources) directory for your reference.

#### Usage for construct_apdus
<pre>
Usage: construct_keymint_apdus options
Valid options are:
-h, --help                        show the help message and exit.
-i, --input  jsonFile 	 Input json file 
-o, --output jsonFile 	 Output json file
</pre>

#### Usage for provision
<pre>
Usage: provision_keymint options
Valid options are:
-h, --help                      show the help message and exit.
-i, --input  jsonFile 	  Input json file 
-s, --provision_stautus   Prints the current provision status.
-l, --lock_provision      Locks the provision state.
</pre>
