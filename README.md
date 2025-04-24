# SaaS Plugin Development Environment

This is the development environment to build and test plugins for
PAM SaaS rotations.

## Setup

Currently, the setup guide is focussed on Linux and macOS. 

### Get the Development Environment

It is assumed that Python 3.8, or greater, has been installed on your system.
The setup will create a Python virtual environment that needs to be activated before
  working on the plugin.

```shell
python -m venv venv
. ./venv/bin/activate
pip install --upgrade pip
git clone git@github.com:Keeper-Security/discovery-and-rotation-saas-dev.git
cd discovery-and-rotation-saas-dev
pip install .
cd ..
```

### Create a work directory

Create a directory in your preferred location. 
This is where the Python plugin will be created and edited.

```shell
mkdir my_work_dir
cd my_work_dir
```

Next you need a Keeper Secrets Manager configuration.

* Have, or create, an Application using the Vault's Secret Manager. 
  The Application being used for a Gateway will work.
* Remember a Shared Folder UID using in the Application. 
  Click on the folder, and then click on the **ⓘ**, and then click on the **UID** value.
* For the Application, add a new device on the Devices tab. 
  For the Method, select Configuration File and JSON, and then click the Download button.
  This will download `config.json`. 
* Moved `config.json` to your work directory, or you can specify the path using 
  `--config` for the commands.

```shell
cp /path/to/downloaded/config.json .
```

## Test with Hello World

Copy the `hello_world.py` file from the `examples` directory to your work directory.

```shell
cd /path/to/my_work_dir
cp /path/to/discovery-and-rotation-saas-dev/exmaples/hello_world.py .
```

### SaaS Config Record

Currently, the SaaS Config record is a **Login** record with custom fields that are
  used to configure the SaaS rotation. 

The command `plugin_test config` is used to make a SaaS Config record in your Vault.
It will prompt you to enter required and optional values.

```shell
(venv) user@machine:~$ plugin_test config --help
Usage: plugin_test config [OPTIONS]

  Create a config file

Options:
  -f, --file TEXT               Plugin python file  [required]
  -s, --shared-folder-uid TEXT  Shared folder UID  [required]
  -t, --title TEXT              SaaS config record tile  [required]
  --config TEXT                 KSM configuration file
  --help                        Show this message and exit.
```
#### Required
* `-f`, `--file` = The Python file
* `-s`, `--shared-folder-uid` = The Shared Folder UID for your Application where 
                               you want to create the SaaS Config record.
* `-t`, `--title` = The title for the SaaS Config record.
#### Optional
*  `--config` = Path to KSM Configuration JSON, if not in the work directory.

Here is an example of the command being run.

```shell
(venv) user@machine:~$ plugin_test config -f hello_world.py -t "Hello World Config" -s XXXX
Required: My Message
This is the message that will be displayed. The field is required.
Enter Value : > This is a required value

Optional: My Optional
This is an optional field, but is secret if it exists
Enter Value  (default: This is a secret): > This is optional, and a secret.

Configuration record UID is YYYY
```
A **record UID** is displayed at the end. This will be needed when using the `plugin_test run`
command.


Here is what the record looks like in the Vault.

![record.png](.images/config_record.png)

### Test the Plugin

The following command wil run the plugin.

```shell
(venv) user@machine:~$ plugin_test run --help
Usage: plugin_test run [OPTIONS]

  Run the plugin

Options:
  -f, --file TEXT               Plugin python file  [required]
  -u, --user-uid TEXT           UID of PAM User record  [required]
  -c, --plugin-config-uid TEXT  UID of plugin config record  [required]
  --configuration-uid TEXT      UID of configuration record
  --fail                        Force run to fail
  --new-password TEXT           New password
  --old-password TEXT           Old password
  --no-old-password             Do not use old password
  --config TEXT                 KSM configuration file
  --help                        Show this message and exit.
                 Show this message and exit.
```
#### Required
* `-f`, `--file` = The Python file
* `-u`, `--user-uid` = The record UID of a PAM User record.
* `-c`, `--plugin-config-uid` = The record UID of the SaaS Config record.
#### Optional
* `--configuration-uid` - If the plugin uses AWS or Azure, the credentials from the
                          configuration record can be supplied to the plugin by setting 
                          this param.
* `--fail` = Force the plugin to fail password rotation.
             This will trigger a rollback of the password change, if plugin supports
             rollback.
* `--new-password` = Manually set the new password.
                     If not set, a random password will be generated.
* `--old-password` = Manually set the old password.
                     If not set, the password on the user record will be used.
* `--no-old-password` = Make the old password blank. 
                        Do not read from user record.
* `--config` = Path to KSM Configuration JSON, if not in the work directory.

Here is an example of the command being run.

```shell
(venv) user@machine:~$ plugin_test run -f hello_world.py -u ZZZZ -c YYYY
2025-04-23 22:41:00,809 kdnrm  INFO: starting rotating of the Hello World user
2025-04-23 22:41:00,809 kdnrm  INFO: rotating the user in Hello World was a success
2025-04-23 22:41:00,809 kdnrm  DEBUG: there were return custom fields
2025-04-23 22:41:00,809 kdnrm  DEBUG: setting the return custom field 'Hello World Label' to value 'Hello there world!!!'
2025-04-23 22:41:00,809 kdnrm  DEBUG: found existing 'Hello World Label' custom field in user record, updating type and value
2025-04-23 22:41:00,809 kdnrm  DEBUG: updating the user record.
Rotation was successful
```
The hello_world.py example sets return values.
These values are added to the PAM User record as custom fields.

![user_record.png](.images/user_record.png)