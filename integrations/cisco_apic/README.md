# User Guide | Keeper Security / CISCO APIC

## Overview

This user guide covers the post-rotation script for the Keeper Security / CISCO APIC integration. 
Details on how to use the post-rotation script are available at the 
  [_Keeper Security online documentation_](https://github.com/Keeper-Security/discovery-and-rotation-saas-dev) and 
  will not be repeated here.

## CISCO API
The [Cisco Application Policy Infrastructure Controller (APIC)](https://www.cisco.com/c/en_in/products/cloud-systems-management/application-policy-infrastructure-controller-apic/index.html) is the central control point for 
  Cisco's Application Centric Infrastructure (ACI) solution. 
It's a software-defined networking (SDN) controller that manages and enforces policies, provides visibility and 
  control over network resources, and orchestrates network provisioning. 

### Required Setup/Information







## Commander

### Create SaaS Configuration Record

In Commander, the `pam action saas config` command is used to create a SaaS Configuration record.
This record currently is a **Login** record where the custom fields are used for settings.

First check if the **Cisco APIC** plugin is available.
Using the `pam action saas config` command with `--list` flag will show all plugins available to your Keeper Gateway.

```
My Vault> pam action saas config -g <GATEWAY UID> --list

Available SaaS Plugins
 * Cisco APIC (Catalog) - Change a user password in Cisco APIC.
 ...
```

If **Cisco APIC** is in the list, you can use this plugin.

Before creating the SaaS Configuration Record, you can get a preview of fields you will be prompted for values.
Next use `pam action saas config`, with `--info` flag and `-p "Cisco APIC"`, to get information about this plugin.
```
My Vault> pam action saas config -g <GATEWAY> -p "Cisco APIC" --info

AWS Cognito
  Type: catalog
  Author: Keeper Security (pam@keepersecurity.com)
  Summary: Change a users password in AWS Cognito.
  Documents: https://github.com/Keeper-Security/discovery-and-rotation-saas-dev/blob/main/integrations/aws_cognito/README.md

  Fields
   * Required: User Pool ID - User Pool ID. 
   * Optional: AWS Access Key ID - AWS Access Key ID. Required if not using a PAM AWS Configuration.
   * Optional: AWS Secret Access Key - AWS Secret Access Key. Required if not using a PAM AWS Configuration.
   * Optional: AWS Region - AWS Region. Required if not using a PAM AWS Configuration.
```

Next use `pam action saas config`, with `--create` flag and `-p "AWS Cognito"`, to create a SaaS Configuration Record.
You will be prompted to enter values for the fields.
Any optional fields that do not have a value will not be added to the record.

```
My Vault> pam action saas config -g <GATEWAY UID> -p "AWS Cognito" --create

User Pool ID
Description: User Pool ID.
Field is required.
Enter value > us-east-2_XXXXXXX

AWS Access Key ID
Description: AWS Access Key ID.
Enter value > AWXXXXXXXXXXXXXXXX

AWS Secret Access Key
Description: AWS Secret Access Key.
Enter value > SECRETKEY

AWS Region
Description: AWS Region.
Enter value > us-east-2

Title for the SaaS configuration record> AWS Cognito Config

Created SaaS configuration record with UID of XXXXXXXXXXXXXX

Assign this configuration to a user using the following command.
  pam action saas add -c XXXXXXXXXXXXXX -u <PAM User Record UID>
  See pam action saas add --help for more information.
```

Once you have a SaaS Configuration record, it can be assigned to a user using the `pam action saas add` command.

```
My Vault> pam action saas add -c XXXXXXXXXXXXXX -u YYYYYYYYYYYY

Added AWS Cognito rotation to the user record.
```

Now when the user's password is rotated, the user's password in AWS Cognito will also be updated.

## Keeper Vault

Currently Keeper Vault does not support SaaS management.


