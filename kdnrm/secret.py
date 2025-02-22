from cryptography.fernet import Fernet
from enum import Enum
import pickle
import io
import json


class Secret:

    redact_text = "XXXX"

    def __init__(self, secret, charset="utf-8"):

        self._value = None
        self.key = Fernet.generate_key()
        self.charset = charset

        if isinstance(secret, Secret) is True:
            self.value = secret.value
        else:
            self.value = secret

    @staticmethod
    def get_value(secret):
        if secret is not None and isinstance(secret, Secret) is True:
            return secret.value
        return secret

    @staticmethod
    def get_secret(value):
        if value is not None and isinstance(value, Secret) is False:
            return Secret(value)
        return value

    @property
    def value(self):
        return pickle.loads(Fernet(self.key).decrypt(self._value))

    @property
    def value_strip(self):
        value = self.value
        if isinstance(value, str) is True:
            return value.strip()
        return value

    @value.setter
    def value(self, secret):
        record_fh = io.BytesIO()
        pickle.dump(secret, record_fh)
        self._value = Fernet(self.key).encrypt(record_fh.getvalue())
        del record_fh

    @property
    def bytes(self):
        value = self.value
        if value is None:
            raise ValueError("Secret is None, cannot convert to bytes.")
        if isinstance(value, str) is True:
            value = value.encode(self.charset)
        if isinstance(value, bytes) is False:
            raise ValueError("Cannot convert secret to bytes.")
        return value

    def __str__(self):
        # If something attempts to print or convert the secret to a string throw an exception.
        # Import exception message here to prevent circular references.
        raise Exception(f"Attempt to use a secret as a string.")

    def __repr__(self):
        return f"Secret({Secret.redact_text})"


class SecretJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Secret) is True:
            return obj.value_strip
        elif isinstance(obj, Enum) is True:
            return obj.value

        return json.JSONEncoder.default(self, obj)
