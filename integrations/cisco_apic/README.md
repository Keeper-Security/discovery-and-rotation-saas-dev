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

Cisco APIC
  Type: catalog
  Author: Keeper Security (pam@keepersecurity.com)
  Summary: Change a user password in Cisco APIC.
  Documents: https://github.com/Keeper-Security/discovery-and-rotation-saas-dev/blob/main/integrations/cisco_apic/README.md

  Fields
   * Required: Admin Name - A user with administrative role.
   * Required: Admin Password - Password for the APIC Admin.
   * Required: URL - The URL to the APIC server.
   * Optional: Verify SSL - Verify that the SSL certificate is valid: 'True' will validate certificates, 'False' 
               will allow self-signed certificates.
```

Next use `pam action saas config`, with `--create` flag and `-p "Cisco APIC"`, to create a SaaS Configuration Record.
You will be prompted to enter values for the fields.
Any optional fields that do not have a value will not be added to the record.

```
My Vault> pam action saas config -g <GATEWAY> -p "Cisco APIC" --create

Admin Name
Description:  user with administrative role.
Field is required.
Enter value > admin

Admin Password
Description: Password for the APIC Admin.
Field is required.
Enter value > ADMIN_PASSWORD

URL
Description: The URL to the APIC server.
Field is required.
Enter value > https://myapicdc.cisco.com

Verify SSL
Description: Verify that the SSL certificate is valid: 'True' will validate certificates, 'False' will allow self-signed certificates.
Enter value (Allowed values: False, True; Enter for default value 'False') >

Title for the SaaS configuration record> Cisco APIC Config

Created SaaS configuration record with UID of XXXXXXXXXXXXXXXXXXXXXX

Assign this configuration to a user using the following command.
  pam action saas add -c XXXXXXXXXXXXXXXXXXXXXX -u <PAM User Record UID>
  See pam action saas add --help for more information.
```

Once you have a SaaS Configuration record, it can be assigned to a user using the `pam action saas add` command.

```
My Vault> pam action saas add -c XXXXXXXXXXXXXX -u YYYYYYYYYYYY

Added AWS Cognito rotation to the user record.
```

Now when the user's password is rotated, the user's password in CiscoAPIC will also be updated.

## Keeper Vault

Currently Keeper Vault does not support SaaS management.


