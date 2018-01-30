#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pytest
from mock import Mock

from lib.vault import VaultKeyring, PasswordSetError, PasswordDeleteError


class TestVaultKeyring:

    @pytest.fixture
    def vault_keyring(self):
        vault_keyring = VaultKeyring(
            vault_url='http://example.com',
            vault_token='28c49cd3-da2f-7a91-c5ac-8e3839e176cc'
        )
        return vault_keyring

    @pytest.fixture
    def mocked_vault(self, vault_keyring, monkeypatch):
        mocked = Mock(return_value={'data': {'secret': 'my-secret'}})
        monkeypatch.setattr(vault_keyring.client, 'read', mocked)
        return mocked

    def test_vault(self, vault_keyring):
        assert vault_keyring.priority == 9
        assert vault_keyring.client is not None

    def test_get_password(self, vault_keyring, mocked_vault):
        assert vault_keyring.get_password('service', 'secret') == 'my-secret'
        mocked_vault.assert_called_once()

    def test_get_password__unknown_secret(self, vault_keyring, mocked_vault):
        assert vault_keyring.get_password('service', 'unknown-secret') is None

    def test_set_password(self, vault_keyring):
        with pytest.raises(PasswordSetError):
            vault_keyring.set_password('service', 'secret', 'letmein')

    def test_delete_password(self, vault_keyring):
        with pytest.raises(PasswordDeleteError):
            vault_keyring.delete_password('service', 'secret')
