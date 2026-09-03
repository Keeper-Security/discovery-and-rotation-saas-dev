from __future__ import annotations
import unittest
from plugin_dev.test_base import MockRecord
from .hello_world import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, Field
from typing import Optional, List


class HelloWorldTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def _record_lookup(record_uid: str) -> List[Field]:
        Log.debug(f"lookup {record_uid}")
        return [
            Field(type='login', values=["ADMIN"]),
            Field(type='password', values=["PASSORD"]),
        ]

    def plugin(
        self,
        prior_password: Optional[Secret] = None,
        field_values: Optional[dict] = None,
        username: Optional[Secret] = Secret("test-user"),
        user_fields: Optional[list] = None) -> SaasPlugin:

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'My Message', 'value': ['This is a hello world plugin.']},
                {'type': 'secret', 'label': 'My Optional', 'value': []},
                {'type': 'text', 'label': 'Admin UID', 'value': ['1234567890123456789012']},
            ]
        )

        return SaasPlugin(user=user,
                          config_record=config_record,
                          record_lookup_func=self._record_lookup)

    def test_requirements(self):
        """
        Check if requirement returns the correct module
        """

        req_list = SaasPlugin.requirements()
        self.assertEqual(0, len(req_list))

    def test_config_schema(self) -> None:
        """Test that the configuration schema is correct."""
        schema = SaasPlugin.config_schema()
        self.assertEqual(3, len(schema))

        schema_ids = [item.id for item in schema]
        self.assertIn("my_msg", schema_ids)
        self.assertIn("my_optional", schema_ids)
        self.assertIn("admin_record_uid", schema_ids)

        # Check required fields
        required_fields = [item for item in schema if item.required]
        self.assertEqual(1, len(required_fields))

    def test_change_password_success(self):
        """
        A happy path test.

        Everything works and the rotation is a success.
        """

        plugin = self.plugin()
        plugin.change_password()
