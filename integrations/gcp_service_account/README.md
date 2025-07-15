# User Guide | Keeper Security / GCP Service Account Key 

## Overview

This plugin creates and manages service account keys in Google Cloud Platform (GCP). It allows you to create new service account keys and delete them as part of a rotation workflow.

## Overview

The GCP Service Account Plugin integrates with Google Cloud IAM to manage service account keys. It creates new keys for the service account specified in the provided service account file and can delete previously created keys for rollback purposes.

## Pre-requisites
To enable service account key rotation using Keeper, ensure the following are set up:

**1. GCP Account:**
You must have access to a GCP project with permission to create service accounts and assign IAM roles.

**2. Google-cloud-IAM library:** Ensure Python is installed, along with the google-cloud-iam library in an activated virtual environment.

    pip install google-cloud-iam

## Steps to Set Up GCP for Service Account Key Rotation
### 1. Create a New Project or Use an Existing One
- Go to the Google Cloud Console.
- From the top nav, click the Project Selector → New Project.
- Enter a project name, choose a billing account, and click Create.

### 2. Create a New Service Account
- Navigate to: **IAM & Admin** → **Service Accounts**
- Click + **CREATE SERVICE ACCOUNT**
- Enter a Service Account Name (e.g., keeper-rotator)
- Click **Create** and **Continue**

### 3. Assign the IAM Role: **Service Account Key Admin**
- In the same wizard, under Grant this service account access, add:

      Role: IAM > Service Account Key Admin (roles/iam.serviceAccountKeyAdmin)

- Click Continue and then Done

### 4. Generate and Download the JSON Key
- From the Service Accounts list, click the newly created service account.
- Go to the Keys tab → Click Add Key > Create new key
- Choose Key Type: JSON and click Create
- The JSON key file will be downloaded to your local system.
- ⚠️ Store this file securely — never check it into version control.

## Steps to Create Keeper Records for GCP
### 1. Create a New Keeper Login Record
- Go to the Keeper Admin Console
- Create a new Record of Type Login named GCP Authentication Record
- Upload the downloaded service_account.json file as an Attachment
- Executing the Script for Rotating GCP Service Account Key
- After setting up the Keeper records and GCP environment, run the following command in your Keeper Gateway environment:
      
      plugin_test run -f <gcp_rotation_script.py> -u <uid_of_gcp_authentication_record> -c <uid_of_gcp_authentication_record>

- The script will generate a new key and update the Keeper record.

