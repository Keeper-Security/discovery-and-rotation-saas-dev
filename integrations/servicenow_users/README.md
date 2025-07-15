# User Guide | Keeper Security / ServiceNow

## Overview
This user guide covers the post-rotation script for the Keeper Security / ServiceNow integration. Details on how to use the post-rotation script are available at the [_Keeper Security online documentation_](https://github.com/Keeper-Security/discovery-and-rotation-saas-dev) and will not be repeated here.

## ServiceNow
ServiceNow is a cloud-based platform as a service (PaaS) that provides a wide range of solutions for automating and managing various enterprise workflows. It focuses on streamlining processes, improving efficiency, and enhancing the user experience through automation and digital transformation.


## Pre-requisites
In order to use the post-rotation script, you will need the following prerequisites:

**1. PySNC Library:** Ensure that the pysnc library is installed in your Python environment. 

    pip install pysnc

## Steps to Test ServiceNow 
### 1. Login to Service Now Developer Page:
- Visit the [ServiceNow Developer Portal](https://signon.service-now.com/x_snc_sso_auth.do?pageId=login).

    <img src="images/sign_up.png" width="350" alt="sign_up">
    
- Sign in using your ServiceNow credentials.
- **Start Building** your ServiceNow developer instance.

    <img src="images/start_building.png" width="350" alt="start_building">

- Typically, launching the dev instance logs you in automatically. If not, follow the steps below to log in manually.
- Click the profile icon and select **Manage Instance Password**.

    <img src="images/manage_instance_1.png" width="350" alt="manage_instance_1">

- In the **Manage Instance Password** section, you’ll find your **instance URL**, **admin username**, and **password**.

    <img src="images/manage_instance_password.png" width="350" alt="manage_instance_password">

- Use these credentials to log into your developer instance.

### 2. Create a User in ServiceNow
- Navigate to **All** > **System Security** > **Users and Groups**, then select the **Users** tab.

    <img src="images/users.png" width="350" alt="users">

- To create a new user, click **New** and fill in the required details.

    <img src="images/new_user.png" width="350" alt="new_user">

- Copy the username.
- Click **Submit** to add the user.

    <img src="images/create_user.png" width="350" alt="create_user">

- To set a password for the new user, select the user and click **Set Password**.
- If the user needs to reset their password after login, enable the **Password needs reset** option.

### 3. Enhance the user admin role:
- Navigate to System Definition → UI Actions.

    <img src="images/ui_actions.png" width="350" alt="ui_actions">

- Search for the "Set Password" UI action and open the corresponding record.

    <img src="images/search_set_password.png" width="350" alt="search_set_password">

- Ensure you have elevated your role (click "Elevate Roles" and select security_admin).

    <img src="images/elevated_role.png" width="350" alt="elevated_role">

- In the "Requires Role" field, insert a new row with the role user_admin.
- Click Update to save the changes.

The user_admin role now has permission to use the Set Password action.

## 4. Create a PAM User Record 
- Create a record of type **PAM User** inside the Keeper Vault.
- Enter the username copied from the previous step.
- This will create a record of type **PAM User**.

    <img src="images/pam_user.png" width="350" alt="pam_user">

### 4. Create a login record 
Once you have your pre-requisites ready, make sure you cover the following:

- Execute the following command in activated virtual environment.

      plugin_test config -f <servicenow_user_python_script> -t "Service Now Instance Admin Details" -s <shared_uid>

      Required: Admin Username
      ServiceNow administrator username.
      Enter Value : >

      Required: Admin Password
      Password for the ServiceNow administrator.
      Enter Value : >

      Required: ServiceNow Instance URL
      Base URL of the ServiceNow instance (e.g. https://<instance>.service-now.com).
      Enter Value : >

      - Admin Username: Admin UserName of ServiceNow instance.
      - Admin Password: Admin Password of ServiceNow instance
      - ServiceNow Instance URL: Service Now Instance URL

- Copy the UUID generated upon successful execution of the command.

    <img src="images/plugin_config.png" width="350" alt="plugin_config">

- This action will create a Record inside the Keeper Vault.

    <img src="images/service_now_instance.png" width="350" alt="service_now_instance">


## 5. Executing the script for rotating password
Once you have your pre-requisites ready, make sure you cover the following:

- Execute the following command in activated virtual environment.
      
      plugin_test run -f <servicenow_user_python_script> -u <uid_created_pam_user_record> -c <copied_uid_of_servicenow_users_authentication_record>

- The above command rotate the ServiceNow user's password.

    <img src="images/plugin_run.png" width="350" alt="plugin_run">

- Keeper Vault PAM User Record is updated.

    <img src="images/success_rotated.png" width="350" alt="success_rotated">