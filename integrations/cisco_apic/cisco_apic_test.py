from __future__ import annotations
import unittest
from unittest.mock import patch
from plugin_dev.test_base import MockRecord
from .cisco_apic import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser
from kdnrm.exceptions import SaasException
from requests import Response
from requests.cookies import RequestsCookieJar
from typing import Optional


class CiscoApicTest(unittest.TestCase):

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

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'Admin Name', 'value': ['ADMIN']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['PASSWORD']},
                {'type': 'secret', 'label': 'Certificate', 'value': ['BEGIN CERTIFICATE']},
                {'type': 'url', 'label': 'URL', 'value': ['https://apic.localhost']},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record)

    def test_requirements(self):
        """
        Check if requirement returns the correct module
        """

        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("requests", req_list[0])

    def test_change_password_success(self):
        """
        A happy path test.

        Everything works and the rotation is a success.
        """

        plugin = self.plugin()

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()
            cookie_jar.set('APIC-cookie', 'APIC TOKEN', domain='example.com', path='/')

            # Mock the token fetch response
            mock_token_res = Response()
            mock_token_res.status_code = 200
            mock_token_res.cookies = cookie_jar

            # Mock the password change response
            mock_change_res = Response()
            mock_change_res.status_code = 200
            mock_change_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_token_res,
                mock_change_res
            ]

            # Do the rotation
            plugin.change_password()

            self.assertEqual("APIC TOKEN", plugin.cookie_token)

            self.assertTrue(plugin.can_rollback)

    def test_missing_custom_field_admin_name(self):
        """
        Missing the custom field for the admin
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MockRecord(
            custom=[
                {'type': 'secret', 'label': 'Admin Password', 'value': ['PASSWORD']},
                {'type': 'secret', 'label': 'Certificate', 'value': ['BEGIN CERTIFICATE']},
                {'type': 'url', 'label': 'URL', 'value': ['https://apic.localhost']},
            ]
        )

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field Admin Name" not in str(err):
                self.fail("did not message containing 'Admin Name'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_admin_password(self):
        """
        Missing the custom field for the admin password
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'Admin Name', 'value': ['ADMIN']},
                {'type': 'secret', 'label': 'Certificate', 'value': ['BEGIN CERTIFICATE']},
                {'type': 'url', 'label': 'URL', 'value': ['https://apic.localhost']},
            ]
        )

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field Admin Password" not in str(err):
                self.fail("did not message containing 'Admin Password'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_url(self):
        """
        Missing the custom field for the URL
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'Admin Name', 'value': ['ADMIN']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['PASSWORD']},
                {'type': 'secret', 'label': 'Certificate', 'value': ['BEGIN CERTIFICATE']},
            ]
        )

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "the field URL" not in str(err):
                self.fail("did not message containing 'URL'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_missing_custom_field_invalid_url(self):
        """
        The URL to the website is not a valid URL
        """

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123")
        )

        config_record = MockRecord(
            custom=[
                {'type': 'text', 'label': 'Admin Name', 'value': ['ADMIN']},
                {'type': 'secret', 'label': 'Admin Password', 'value': ['PASSWORD']},
                {'type': 'secret', 'label': 'Certificate', 'value': ['BEGIN CERTIFICATE']},
                {'type': 'url', 'label': 'URL', 'value': ['ftp://apic.localhost']},
            ]
        )

        try:
            SaasPlugin(user=user, config_record=config_record)
            raise Exception("should have failed")
        except SaasException as err:
            if "does not appears to be a URL" not in str(err):
                self.fail("did not message containing 'does not appears to be a URL'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_change_password_token_http_error(self):
        """
        Cisco returns a 500 error when getting the token.
        """

        plugin = self.plugin()

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()
            cookie_jar.set('APIC-cookie', 'APIC TOKEN', domain='example.com', path='/')

            # Mock the token fetch response
            mock_token_res = Response()
            mock_token_res.status_code = 500
            mock_token_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_token_res,
            ]

            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Failed to extract cookie token" not in str(err):
                    self.fail("did not message containing 'Failed to extract cookie token'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_token_no_cookie(self):
        """
        Cisco doesn't return a cookie.
        """

        plugin = self.plugin()

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()

            # Mock the token fetch response
            mock_token_res = Response()
            mock_token_res.status_code = 200
            mock_token_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_token_res,
            ]

            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Failed to extract cookie token" not in str(err):
                    self.fail("did not message containing 'Failed to extract cookie token'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_set_failed(self):
        """
        Cisco reject the password change.
        """

        plugin = self.plugin()

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()
            cookie_jar.set('APIC-cookie', 'APIC TOKEN', domain='example.com', path='/')

            # Mock the token fetch response
            mock_token_res = Response()
            mock_token_res.status_code = 200
            mock_token_res.cookies = cookie_jar

            # Mock the password change response
            mock_change_res = Response()
            mock_change_res.status_code = 500
            mock_change_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_token_res,
                mock_change_res
            ]

            try:
                plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Failed to change password" not in str(err):
                    self.fail("did not message containing 'Failed to change password'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_rollback_password_success(self):
        """
        A happy path test for rollback.

        Everything works and the rollback is a success.
        """

        plugin = self.plugin(prior_password=Secret("OldPassword456"))

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()
            cookie_jar.set('APIC-cookie', 'APIC TOKEN', domain='example.com', path='/')

            # Mock the token fetch response
            mock_token_res = Response()
            mock_token_res.status_code = 200
            mock_token_res.cookies = cookie_jar

            # Mock the password change response
            mock_change_res = Response()
            mock_change_res.status_code = 200
            mock_change_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_token_res,
                mock_change_res
            ]

            # Do the rotation
            plugin.rollback_password()

    def test_rollback_password_no_prior_password(self):
        """
        No prior password to roll back to.
        """

        plugin = self.plugin()

        try:
            plugin.rollback_password()
            raise Exception("should have failed")
        except SaasException as err:
            if "no current password" not in str(err):
                self.fail("did not message containing 'no current password'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_rollback_password_http_error(self):
        """
        Cisco won't roll back to password.
        """

        plugin = self.plugin(prior_password=Secret("OldPassword456"))

        with patch("requests.post") as mock_post:
            cookie_jar = RequestsCookieJar()
            cookie_jar.set('APIC-cookie', 'APIC TOKEN', domain='example.com', path='/')

            # Mock the password change response
            mock_change_res = Response()
            mock_change_res.status_code = 500
            mock_change_res.cookies = cookie_jar

            mock_post.side_effect = [
                mock_change_res
            ]

            try:
                plugin.rollback_password()
                raise Exception("should have failed")
            except SaasException as err:
                if "Failed to roll back password" not in str(err):
                    self.fail("did not message containing 'Failed to roll back password'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")
