import json
from dataclasses import dataclass
from decimal import Decimal
from typing import Tuple, Iterable, Any

from stellar_sdk import Asset, Keypair, Network, Server, TransactionBuilder, Account


@dataclass
class Balance:
    asset: Asset
    balance: Decimal


def get_account(server, secret_key) -> Tuple[Account, Keypair]:
    source_keypair = Keypair.from_secret(secret_key)
    return server.load_account(account_id=source_keypair.public_key), source_keypair


def parse_path(path: Iterable[dict]) -> list[Asset]:
    return [
        Asset.native() if p['asset_type'] == 'native' else Asset(p['asset_code'], p['asset_issuer'])
        for p in path
    ]


def get_path(server, source: Asset, destination: Asset, source_amount: Decimal) -> Tuple[list[Asset], Decimal]:
    paths = server.strict_send_paths(source, source_amount, [destination]).call()['_embedded']['records']
    best_path = reversed(sorted(paths, key=lambda p: Decimal(p['destination_amount']))).__next__()
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


def convert_asset(
        server: Server,
        account: Account,
        keypair: Keypair,
        source: Asset,
        source_balance: Decimal,
        destination: Asset,
        destination_balance: Decimal,
        path: list[Asset]
):
    transaction = (
        TransactionBuilder(
            source_account=account,
            network_passphrase=Network.PUBLIC_NETWORK_PASSPHRASE,
            base_fee=100,
        )
        .append_path_payment_strict_receive_op(
            destination=account.universal_account_id,
            send_asset=source,
            send_max=source_balance,
            dest_asset=destination,
            dest_amount=destination_balance,
            path=path,
        )
        .set_timeout(30)
        .build()
    )

    # how to ask lobstr vault signature instead of failing in place?
    # extra_signers = [
    #     s for s in account.load_ed25519_public_key_signers()
    #     if s.account_id != account.universal_account_id
    # ]

    transaction.sign(keypair)
    _response = server.submit_transaction(transaction)


def main(secret_key: str, assets_to_convert: list, target_asset: str):
    server = Server(horizon_url="https://horizon.stellar.org")
    account, keypair = get_account(server, secret_key)
    dest_asset = get_trusted_asset(account, target_asset)
    balances = get_balances(account)
    for balance in balances:
        if balance.asset.code not in assets_to_convert:
            continue

        print(balance.asset.code, balance.asset.issuer, balance.balance)
        path, dest_amount = get_path(server, balance.asset, dest_asset, balance.balance)
        print(f'converting {balance.balance} of {balance.asset.code} into {dest_amount} of {dest_asset.code}')
        print(f'path: {path}')
        convert_asset(server, account, keypair, balance.asset, balance.balance, dest_asset, dest_amount, path)


if __name__ == '__main__':
    with open('config.json', 'r') as config_file:
        config = json.loads(config_file.read())
    main(config['secret_key'], config['assets_to_convert'], config['target_asset'])
