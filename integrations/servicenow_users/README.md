# User Guide | Keeper Security / ServiceNow

## Overview
This user guide covers the post-rotation script for the Keeper Security / ServiceNow integration. Details on how to use the post-rotation script are available at the [_Keeper Security online documentation_](https://github.com/Keeper-Security/discovery-and-rotation-saas-dev) and will not be repeated here.

## ServiceNow
ServiceNow is a cloud-based platform as a service (PaaS) that provides a wide range of solutions for automating and managing various enterprise workflows. It focuses on streamlining processes, improving efficiency, and enhancing the user experience through automation and digital transformation.


## Pre-requisites
In order to use the post-rotation script, you will need the following prerequisites:

**1. Requests Library:** Ensure that the requests library is installed in your Python environment. This library is necessary for making HTTP requests to Service-Now.

**2. Requests library installation:** The Requests library allows you to send HTTP requests easily. Activate a Python virtual environment in your Keeper Gateway environment and install the library using the following command:

    pip install requests

## Steps to Test ServiceNow 
### 1. Login to Service Now Developer Page:
- Go to the [Service Now Developer](https://signon.service-now.com/x_snc_sso_auth.do?pageId=login) page. 
- Log in with your ServiceNow credentials.
- 