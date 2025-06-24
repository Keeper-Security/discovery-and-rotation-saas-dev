from __future__ import annotations
import unittest
from unittest.mock import MagicMock, patch
from integrations.aws_cognito.aws_cognito import SaasPlugin
from kdnrm.secret import Secret
from kdnrm.log import Log
from kdnrm.saas_type import SaasUser, AwsConfig
from kdnrm.exceptions import SaasException
from botocore.exceptions import ClientError
from plugin_dev.test_base import MockRecord
from typing import Optional, Any, List


class AwsCognitoTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        Log.init()
        Log.set_log_level("DEBUG")

    @staticmethod
    def plugin(prior_password: Optional[Secret] = None,
               provider_config: Optional[Any] = None,
               field_values: List[Any] = None):

        if field_values is None:
            field_values = [
                "POOL ID",
                "ACCESS ID",
                "SECRET KEY",
                "us-east-2"
            ]

        user = SaasUser(
            username=Secret("jdoe"),
            new_password=Secret("NewPassword123"),
            prior_password=prior_password
        )

        config_record = MockRecord(
            custom=[
                {'type': 'secret', 'label': 'User Pool ID', 'value': [field_values[0]]},
                {'type': 'text', 'label': 'AWS Access Key ID', 'value': [field_values[1]]},
                {'type': 'secret', 'label': 'AWS Secret Access Key', 'value': [field_values[2]]},
                {'type': 'text', 'label': 'AWS Region', 'value': [field_values[3]]},
            ]
        )

        return SaasPlugin(user=user, config_record=config_record, provider_config=provider_config)

    def test_requirements(self):
        """
        Check if requirement returns the correct module.
        """

        req_list = SaasPlugin.requirements()
        self.assertEqual(1, len(req_list))
        self.assertEqual("boto3", req_list[0])

    def test_change_password_success(self):
        """
        A happy path test.

        Everything works and the rotation is a success.
        """

        plugin = self.plugin()

        with patch("boto3.client") as mock_client:
            mock_cognito_idp = MagicMock()
            mock_client.return_value = mock_cognito_idp

            plugin.change_password()

            mock_cognito_idp.admin_set_user_password.assert_called_once_with(
                UserPoolId="POOL ID",
                Username="jdoe",
                Password="NewPassword123",
                Permanent=True
            )

            args, kwargs = mock_client.call_args

            self.assertEqual("cognito-idp", args[0])
            self.assertEqual("ACCESS ID", kwargs["aws_access_key_id"])
            self.assertEqual("SECRET KEY", kwargs["aws_secret_access_key"])
            self.assertEqual("us-east-2", kwargs["region_name"])

        self.assertTrue(plugin.can_rollback)

    def test_change_password_provider_success(self):
        """
        A happy path test using AWS creds from PAM AWS configuration record.

        Everything works and the rotation is a success.
        """

        aws_config = AwsConfig(
            aws_access_key_id=Secret("PAM CONFIG ACCESS ID"),
            aws_secret_access_key=Secret("PAM CONFIG SECRET KEY"),
            region_names=["us-west-2", "us-east-2"]
        )

        plugin = self.plugin(field_values=["POOL ID", None, None, None], provider_config=aws_config)

        with patch("boto3.client") as mock_client:
            mock_cognito_idp = MagicMock()
            mock_client.return_value = mock_cognito_idp

            plugin.change_password()

            mock_cognito_idp.admin_set_user_password.assert_called_once_with(
                UserPoolId="POOL ID",
                Username="jdoe",
                Password="NewPassword123",
                Permanent=True
            )

            args, kwargs = mock_client.call_args

            self.assertEqual("cognito-idp", args[0])
            self.assertEqual("PAM CONFIG ACCESS ID", kwargs["aws_access_key_id"])
            self.assertEqual("PAM CONFIG SECRET KEY", kwargs["aws_secret_access_key"])
            self.assertEqual("us-west-2", kwargs["region_name"])

    def test_change_password_missing_user_pool_id(self):

        try:
            plugin = self.plugin(field_values=[None, "ACCESS ID", "SECRET KEY", "us-east-1"])
            with patch("boto3.client") as mock_client:
                mock_cognito_idp = MagicMock()
                mock_client.return_value = mock_cognito_idp

                plugin.change_password()
            raise Exception("should have failed")
        except SaasException as err:
            print(str(err))
            if "User Pool ID" not in str(err):
                self.fail("did not message containing 'User Pool ID'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_change_password_missing_access_key_id_no_session(self):

        # If you have a .aws directory in your home directory, it will consider a stored credentials as a session.
        # Prevent this.
        with patch("integrations.aws_cognito.aws_cognito.SaasPlugin._using_session") as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["POOL_ID", None, "SECRET KEY", "us-east-1"])
                with patch("boto3.client") as mock_client:
                    mock_cognito_idp = MagicMock()
                    mock_client.return_value = mock_cognito_idp

                    plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                print(str(err))
                if "AWS Access Key ID" not in str(err):
                    self.fail("did not message containing 'AWS Access Key ID'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_missing_access_secret_key_no_session(self):

        # If you have a .aws directory in your home directory, it will consider a stored credentials as a session.
        # Prevent this.
        with patch("integrations.aws_cognito.aws_cognito.SaasPlugin._using_session") as mock_session:
            mock_session.return_value = None

            try:
                plugin = self.plugin(field_values=["POOL_ID", "ACCESS ID", None, "us-east-1"])
                with patch("boto3.client") as mock_client:
                    mock_cognito_idp = MagicMock()
                    mock_client.return_value = mock_cognito_idp

                    plugin.change_password()
                raise Exception("should have failed")
            except SaasException as err:
                print(str(err))
                if "AWS Secret Access Key" not in str(err):
                    self.fail("did not message containing 'AWS Secret Access Key'")
            except Exception as err:
                self.fail(f"got wrong exception: {err}")

    def test_change_password_missing_region(self):

        try:
            plugin = self.plugin(field_values=["POOL_ID", "ACCESS ID", "SECRET KEY", None])
            with patch("boto3.client") as mock_client:
                mock_cognito_idp = MagicMock()
                mock_client.return_value = mock_cognito_idp

                plugin.change_password()
            raise Exception("should have failed")
        except SaasException as err:
            print(str(err))
            if "AWS Region" not in str(err):
                self.fail("did not message containing 'AWS Region'")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_user_not_found(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "UserNotFoundException",
                            "Message": "User does not exist.",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "user was not found" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_invalid_param(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "InvalidParameterException",
                            "Message": "The parameter is invalid.",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "appears to be invalid" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_not_auth(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "NotAuthorizedException",
                            "Message": "User is disabled",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "user is either disabled" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_too_many_requests(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "TooManyRequestsException",
                            "Message": "Too many requests",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "Exceeded the AWS limit for requests" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_internal_error(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "InternalErrorException",
                            "Message": "Internal Server Error",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "internal exception" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_admin_set_user_password_unknown_error(self):

        try:
            plugin = self.plugin()
            with patch("boto3.client") as mock_client:
                mock_client.side_effect = ClientError(
                    {
                        "Error": {
                            "Code": "Something",
                            "Message": "Unknonw error",
                        }
                    }, operation_name="AdminSetUserPassword"
                )
                plugin.change_password()
                self.fail("should have gotten an exception")
        except SaasException as err:
            if "Could not change AWS Cognito password" not in str(err):
                self.fail("did not get correct message")
        except Exception as err:
            self.fail(f"got wrong exception: {err}")

    def test_rollback_success(self):
        """
        A happy path test.

        Everything works and the rotation is a success.
        """

        plugin = self.plugin(prior_password=Secret("OldPassword123"))

        with patch("boto3.client") as mock_client:
            mock_cognito_idp = MagicMock()
            mock_client.return_value = mock_cognito_idp

            # Do `change_password` to set the client.
            # The boto3
            plugin.rollback_password()

            # FAKE FAILURE

