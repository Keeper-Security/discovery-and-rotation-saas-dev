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

cp discovery-and-rotation-saas-dev/exmaples/hello_world.py
plugin_test config -f hello_world.py -t "Hello World Config"
plugin_test run -f hello_world.py -u USER_RECROD_UID -c USER_RECORD_

```