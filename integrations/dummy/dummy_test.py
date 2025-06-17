from __future__ import annotations
import unittest
from unittest.mock import MagicMock
from .dummy import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from typing import Optional


class DummyTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None):

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MagicMock()
        config_record.dict = {
            'custom': [
                {'type': 'text', 'label': 'Dummy Text', 'value': ['SOME TEXT']},
                {'type': 'text', 'label': 'Font Type', 'value': ['bulbhead']},
            ]
        }
        config_record.title = 'Dummy Config'
        config_record.type = 'login'
        config_record.uid = 'fakeUid'

        # The param checker does not like MagicMock.
        config_record.get_custom_field_value.side_effect = [
            "SOME TEXT",
            "bulbhead"
        ]

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """
        Check if requirement returns the correct module
        """

        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("art", req_list[0])

    def test_change_password(self):
        """
        A happy path test.

        Everything works and the rotation is a success.
        """

        plugin = self.plugin()
        plugin.change_password()

        self.assertFalse(plugin.can_rollback)
