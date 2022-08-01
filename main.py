import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Iterable, Tuple

import requests
from stellar_sdk import (Account, Asset, Keypair, Network, Server,
                         TransactionBuilder, TransactionEnvelope)


@dataclass
class Balance:
    asset: Asset
    balance: Decimal


def get_account(server, secret_key) -> Account:
    source_keypair = Keypair.from_secret(secret_key)
    return server.load_account(account_id=source_keypair.public_key)


def parse_path(path: Iterable[dict]) -> list[Asset]:
    return [
        Asset.native() if p['asset_type'] == 'native' else Asset(p['asset_code'], p['asset_issuer'])
        for p in path
    ]


def get_path(server, source: Asset, destination: Asset, source_amount: Decimal) -> Tuple[list[Asset], Decimal]:
    paths = server.strict_send_paths(source, source_amount, [destination]).call()['_embedded']['records']
    try:
        best_path = reversed(sorted(paths, key=lambda p: Decimal(p['destination_amount']))).__next__()
    except StopIteration:
        return None, None
    return parse_path(best_path['path']), Decimal(best_path['destination_amount'])


def get_balances(account: Account):
    return [
        Balance(
            Asset.native() if b['asset_type'] == 'native' else Asset(b['asset_code'], b['asset_issuer']),
            Decimal(b['balance'])
        )
        for b in account.raw_data['balances']
        if Decimal(b['balance']) > 0
    ]


def get_trusted_asset(account: Account, asset_code: str) -> Asset:
    return [
        a for a in [
            Asset.native() if b['asset_type'] == 'native' else Asset(b['asset_code'], b['asset_issuer'])
            for b in account.raw_data['balances']
        ]
        if a.code == asset_code
    ][0]


def submit_transaction_to_lobstr_vault(transaction_xdr: str):
    response = requests.post(
        'https://vault.lobstr.co/api/transactions/',
        json={
            'xdr': transaction_xdr
        }
    )
    if response.status_code != 201:
        raise Exception(response.text)

    print("submitted to Lobstr Vault")


def sign_transaction(transaction: TransactionEnvelope, account: Account, keypairs: list[Keypair]):
    valid_signers = [a.account_id for a in account.load_ed25519_public_key_signers() if a.weight]
    keypairs = [k for k in keypairs if k.public_key in valid_signers]
    for keypair in keypairs:
        transaction.sign(keypair)


def submit_transaction(server: Server, account: Account, transaction: TransactionEnvelope):
    valid_signers = [a.account_id for a in account.load_ed25519_public_key_signers() if a.weight]
    # should contain GA2T6GR7VXXXBETTERSAFETHANSORRYXXXPROTECTEDBYLOBSTRVAULT in signers
    # https://github.com/Lobstrco/Vault-iOS/blob/master/README.md#developers-integrate-lobstr-vault-with-your-service
    if "GA2T6GR7VXXXBETTERSAFETHANSORRYXXXPROTECTEDBYLOBSTRVAULT" in valid_signers:
        submit_transaction_to_lobstr_vault(transaction.to_xdr())
    else:
        response = server.submit_transaction(transaction)
        print(response)


def main(secret_key: str, extra_signers: list[str], assets_to_convert: list, target_asset: str):
    server = Server(horizon_url="https://horizon.stellar.org")
    account = get_account(server, secret_key)
    dest_asset = get_trusted_asset(account, target_asset)
    balances = get_balances(account)
    transaction_builder = TransactionBuilder(
        source_account=account,
        network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
        base_fee=100,
    ).set_timeout(300)

    operations_exists = False

    for balance in balances:
        if balance.asset.code not in assets_to_convert:
            continue

        print(balance.asset.code, balance.asset.issuer, balance.balance)
        path, dest_amount = get_path(server, balance.asset, dest_asset, balance.balance)
        if not path:
            print(f'unable to find path for {balance.balance} of {balance.asset.code}')
            continue

        print(f'converting {balance.balance} of {balance.asset.code} into {dest_amount} of {dest_asset.code}')
        path_str = ' -> '.join([balance.asset.code] + [a.code for a in path] + [dest_asset.code])
        print(f'path: {path_str}')

        transaction_builder.append_path_payment_strict_receive_op(
            destination=account.universal_account_id,
            send_asset=balance.asset,
            send_max=balance.balance,
            dest_asset=dest_asset,
            dest_amount=dest_amount,
            path=path,
        )
        operations_exists = True

    if not operations_exists:
        print('No operations to add. stopping')
        return

    signatures = [Keypair.from_secret(key) for key in [secret_key] + extra_signers]
    transaction = transaction_builder.build()
    sign_transaction(transaction, account, signatures)
    submit_transaction(server, account, transaction)


if __name__ == '__main__':
    with open('config.json', 'r') as config_file:
        config = json.loads(config_file.read())
    main(config['secret_key'], config['extra_signers'], config['assets_to_convert'], config['target_asset'])
