#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import keyring
import hvac
from keyring.backend import KeyringBackend
from keyring.errors import PasswordSetError, PasswordDeleteError

from .error import ConfigError


logging.basicConfig()
LOG = logging.getLogger("lib/vault")


class VaultBackend:
    VAULT = 'vault'
    KEYRING = 'keyring'


class VaultKeyring(KeyringBackend):
    """
    Vault-based implementation of keyring.

    It uses the python HashiCorp Vault API to manage the secrets
    directly in the local or remote server.
    """

    priority = 9

    def __init__(self, vault_url, vault_token):
        super(VaultKeyring, self).__init__()

        self.client = hvac.Client(
            url=vault_url, token=vault_token
        )

    def get_password(self, service, key):
        """
        Get secret of the key for the service
        """
        ret = self.client.read('secret/{}'.format(service))
        try:
            return ret['data'][key]
        except:
            LOG.info(
                "Unable to get secret key for the service: "
                "service={} key={}".format(service, key)
            )
            return None

    def set_password(self, service, key, value):
        """
        Set secret for the key of the service
        """
        raise PasswordSetError(
            "Write secret to vault backend is disabled"
        )

    def delete_password(self, service, key):
        """
        Delete the secret for the key of the service.
        """
        raise PasswordDeleteError(
            "Delete secret from vault backend is disabled"
        )


class Vault(object):
    """
    Base class for vault used to manage service secrets.
    """

    def __init__(self, service_name, vault_backend):
        self._service_name = service_name

        if vault_backend == VaultBackend.KEYRING:
            LOG.info("The keyring backend is used as the secret storage")
        elif vault_backend == VaultBackend.VAULT:
            LOG.info(
                "The vault backend is selected to access the "
                "secret storage"
            )

            LOG.info("Get the vault URL from system keyring")
            vault_url = self.get_secret('vault_url')

            LOG.info("Get the vault token from system keyring")
            vault_token = self.get_secret('vault_token')

            vault_keyring = VaultKeyring(
                vault_url=vault_url, vault_token=vault_token
            )
            keyring.set_keyring(vault_keyring)
            LOG.info("The vault backend is used to access the secret storage")
        else:
            raise ConfigError(
                "Invalid vault backend: '{}', e.g. only 'keyring' "
                "and 'vault' values are allowed".format(vault_backend)
            )

    def set_secret(self, key, value):
        """
        Set secret key/value pairs into a vault.
        """
        try:
            keyring.set_password(self._service_name, key, value)
        except PasswordSetError:
            LOG.exception("Unable to save secret on vault")
            return

        LOG.info(
            "Secret key '{}' for service '{}' has been saved".format(
                key, self._service_name))

    def get_secret(self, key):
        """
        Retrieve secret value for a key from vault.
        """
        return keyring.get_password(self._service_name, key)


def _get_vault_attrs(args):
    connector_name= args.connector
    secret_key = args.key
    secret_value = args.value
    return (connector_name, secret_key, secret_value)


def save_secret_to_vault(args):
    service_name, secret_key, secret_value = _get_vault_attrs(args)

    vault = Vault(service_name, vault_backend=VaultBackend.KEYRING)
    vault.set_secret(secret_key, secret_value)
