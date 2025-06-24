# Testing

A unit test is required. 
The test has a minimum 70% coverage limit.
If the coverage is less than 70%, the push request will not be accepted.

## Mock Record

To mock the configuration record the `MockRecord` from `plugin_dev.test_base` 
  is used.
It is class subclass of `Record` from [Keeper Secrets Manager SDK](https://github.com/Keeper-Security/secrets-manager/blob/a95f3a01e55b9552805e65d365d33227ae51fe57/sdk/python/core/keeper_secrets_manager_core/dto/dtos.py#L23).


```python
from __future__ import annotations
import unittest
from .my_plugin import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.saas_type import SaasUser
from plugin_dev.test_base import MockRecord
from typing import Optional


class MyPluginTest(unittest.TestCase):

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None):

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'My Custom Field', 'value': ['Hello']},
                {'type': 'text', 'label': 'Another Custom FIeld', 'value': ['There']},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)
```