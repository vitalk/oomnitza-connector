#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import keyring
from keyring.errors import PasswordSetError

LOG = logging.getLogger("lib/vault")


class Vault(object):
    """
    Base class for vault used to manage service secrets.
    """

    def __init__(self, service_name):
        self._service_name = service_name

    def set_secret(self, key, value):
        """
        Set secret key/value pairs into a vault.
        """
        try:
            keyring.set_password(self._service_name, key, value)
        except PasswordSetError:
            LOG.exception("Unable to save secret on vault")

        LOG.info(
            "Secret key '{}' for service '{}' has been saved".format(
                key, self._service_name))

    def get_secret(self, key):
        """
        Retrieve secret value for a key from vault.
        """
        return keyring.get_password(self._service_name, key)


def save_secret_to_vault(args):
    connector_name= args.connector
    secret_key = args.key
    secret_value = args.value

    vault = Vault(connector_name)
    vault.set_secret(secret_key, secret_value)
