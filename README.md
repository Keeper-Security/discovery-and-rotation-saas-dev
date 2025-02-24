# SaaS Plugin Development Environment

## TL;DR

Prior to checking out the code, create a KSM device for the application
that PAM Gateway uses. 
Use the Method Configuration File to get the client configuration. 
Download a JSON configuration file.
It will download a `config.json`, but it needs to be renamed as `client-config.json`.

```shell
mkdir my_work_dir
cd my_work_dir
cp /path/to/downloaded/config.json ./client-config.json

python -m venv venv
. ./venv/bin/activate
pip install --upgrade pip
git clone git@github.com:Keeper-Security/discovery-and-rotation-saas-dev.git
cd discovery-and-rotation-saas-dev
pip install .
cd ..

cp discovery-and-rotation-saas-dev/exmaples/hello_world.py .
plugin_test config -f hello_world.py -t "Hello World Config" -s SHARED_FOLDER_UID
plugin_test run -f hello_world.py -u USER_RECROD_UID -c CONFIG_RECORD_UID
```


## Steps

## Work Directory

To keep a clean environment, create a directory to work inside.

### Make a device configuration

This development environment will need access to the Vault.
This is done using KSM. 
Using KSM requires a configuration. 
In the Vault, under **Secret Manager** find the **Application** the gateway uses and create a new device.
Download the JSON configuration.