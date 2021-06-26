# Provisioning tool
This directory contains provisioning tool which helps in provisioning 
the secure element by using the APIs exposed by Provision library.
This tool takes the input parameters from json file.

#### Build
This tool can be built along with aosp build. It has dependency on 
[libjc_common](../HAL/keymaster/Android.bp) and
[libjc_provision](Android.bp).

#### Sample resources for quick testing
Two sample json files are located in this directory with names sample_json_cf.txt
and sample_json_gf.txt for your reference. Use sample_json_cf.txt for cuttlefish
target and use sample_json_gf.txt for goldfish target. Also the required certificates
and keys can be found in [test_resources](test_resources) directory. Copy the
certificates and the key into the emulator/device filesystem in their respective
paths mentioned in the sample json file.

#### Usage
<pre>
Usage: provision_tool options
Valid options are:
-h, --help                        show the help message and exit.
-a, --all jsonFile                Executes all the provision commands.
-k, --attest_key jsonFile         Provision attestation key.
-c, --cert_chain jsonFile         Provision attestation certificate chain.
-p, --cert_params jsonFile        Provision attestation certificate parameters.
-i, --attest_ids jsonFile         Provision attestation IDs.
-r, --shared_secret jsonFile      Provision pre-shared secret.
-b, --set_boot_params jsonFile    Provision boot parameters.
-s, --provision_stautus           Prints the current provision status.
-l, --lock_provision              Locks the provision commands.
</pre>
