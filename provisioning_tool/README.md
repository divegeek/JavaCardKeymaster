# Provisioning tool
This directory contains provisioning tool which helps in provisioning 
the secure element by using the APIs exposed by Provision library.
This tool takes the input parameters from json file. A sample
json file is located in this directory with name sample_json.txt for
your reference.

#### Build
This tool can be built along with aosp build. It has dependency on 
[libjc_common](https://github.com/BKSSMVenkateswarlu/JavaCardKeymaster/blob/master/HAL/keymaster/Android.bp) and
libjc_provision.

#### Usage
Usage: provision_tool *options*\
Valid options are:\
-h, --help                        show the help message and exit.\
-a, --all jsonFile                Executes all the provision commands.\
-k, --attest_key jsonFile         Provision attestation key.\
-c, --cert_chain jsonFile         Provision attestation certificate chain.\
-p, --cert_params jsonFile        Provision attestation certificate parameters.\
-i, --attest_ids jsonFile         Provision attestation IDs.\
-r, --shared_secret jsonFile      Provision pre-shared secret.\
-b, --set_boot_params jsonFile    Provision boot parameters.\
-s, --provision_stautus           Prints the current provision status.\
-l, --lock_provision              Locks the provision commands.
