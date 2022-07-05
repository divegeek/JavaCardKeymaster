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
Usage: Please give json files with values as input to generate the apdus command.
Please refer to sample_json files available in the folder for reference.
Sample json files are written using hardcode parameters to be used for 
testing setup on cuttlefilsh emulator and goldfish emulators
construct_keymint_apdus [options]
Valid options are:
-h, --help    show this help message and exit.
-i, --input  jsonFile 	 Input json file 
-o, --output jsonFile 	 Output json file
</pre>

#### Usage for provision
<pre>
Usage: Please consturcture the apdu(s) with help of construct apdu tool and
pass the output file to this utility.
provision_keymint [options] 
Valid options are: 
-h, --help    show this help message and exit. 
-i, --input  jsonFile 	 Input json file 
-s, --provision_status jsonFile    Gets the provision status of applet. 
-l, --lock_provision jsonFile 	   OEM provisioning lock. 
-f, --se_factory_lock jsonFile 	   SE Factory provisioning lock. 
-u, --unlock_provision jsonFile    Unlock OEM provisioning. 
</pre>
