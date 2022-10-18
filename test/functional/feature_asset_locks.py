#!/usr/bin/env python3

# Copyright (c) 2022 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import hashlib
from decimal import Decimal
from io import BytesIO

from test_framework.authproxy import JSONRPCException
from test_framework.key import ECKey
from test_framework.messages import (
    FromHex,
    CAssetLockTx,
    CAssetUnlockTx,
    COutPoint,
    CTxOut,
    CTxIn,
    COIN,
    CTransaction,
)
from test_framework.script import (
    hash160,
    CScript,
    OP_HASH160,
    OP_RETURN,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUALVERIFY,
)
from test_framework.test_framework import DashTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    wait_until,
)

llmq_type_test = 100
tiny_amount = int(Decimal("0.0007") * COIN)

def create_assetlock(node, coin, amount, pubkey):
    inputs = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]

    credit_outputs = CTxOut(amount, CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG]))

    lockTx_payload = CAssetLockTx(1, 0, [credit_outputs])

    remaining = int(COIN * coin['amount']) - tiny_amount - credit_outputs.nValue

    tx_output_ret = CTxOut(credit_outputs.nValue, CScript([OP_RETURN, b""]))
    tx_output = CTxOut(remaining, CScript([pubkey, OP_CHECKSIG]))

    lock_tx = CTransaction()
    lock_tx.vin = inputs
    lock_tx.vout = [tx_output, tx_output_ret] if remaining > 0 else [tx_output_ret]
    lock_tx.nVersion = 3
    lock_tx.nType = 8 # asset lock type
    lock_tx.vExtraPayload = lockTx_payload.serialize()

    lock_tx = node.signrawtransactionwithwallet(lock_tx.serialize().hex())
    return FromHex(CTransaction(), lock_tx["hex"])


def create_assetunlock(node, mninfo, index, withdrawal, pubkey=None):
    def check_sigs(mninfo, id, msgHash):
        for mn in mninfo:
            if not mn.node.quorum("hasrecsig", llmq_type_test, id, msgHash):
                return False
        return True

    def wait_for_sigs(mninfo, id, msgHash, timeout):
        wait_until(lambda: check_sigs(mninfo, id, msgHash), timeout = timeout)

    tx_output = CTxOut(int(withdrawal) - tiny_amount, CScript([pubkey, OP_CHECKSIG]))

    # request ID = sha256("plwdtx", index)
    sha256 = hashlib.sha256()
    sha256.update(("plwdtx" + str(index)).encode())
    id = sha256.digest()[::-1].hex()

    height = node.getblockcount()
    quorumHash = mninfo[0].node.quorum("selectquorum", llmq_type_test, id)["quorumHash"]
    unlockTx_payload = CAssetUnlockTx(
        version = 1,
        index = index,
        fee = tiny_amount,
        requestedHeight = height,
        quorumHash = int(quorumHash, 16),
        quorumSig = b'\00' * 96)

    unlock_tx = CTransaction()
    unlock_tx.vin = []
    unlock_tx.vout = [tx_output]
    unlock_tx.nVersion = 3
    unlock_tx.nType = 9 # asset unlock type
    unlock_tx.vExtraPayload = unlockTx_payload.serialize()

    print(f'unlock {PA(withdrawal)} on {height} by {index}')
    unlock_tx.calc_sha256()
    msgHash = format(unlock_tx.sha256, '064x')

    for mn in mninfo:
        mn.node.quorum("sign", llmq_type_test, id, msgHash)

    wait_for_sigs(mninfo, id, msgHash, 5)

    recsig = mninfo[0].node.quorum("getrecsig", llmq_type_test, id, msgHash)

    unlockTx_payload.quorumSig = bytearray.fromhex(recsig["sig"])
    unlock_tx.vExtraPayload = unlockTx_payload.serialize()
    return unlock_tx

def get_credit_pool_amount(node, block_hash = None):
    if block_hash is None:
        block_hash = node.getbestblockhash()
    block = node.getblock(block_hash)
    return int(COIN * block['cbTx']['assetLockedAmount'])

def PA(amount):
    return f'{int(amount) // COIN}.{int(amount) % COIN}'

class AssetLocksTest(DashTestFramework):
    def set_test_params(self):
        self.set_dash_test_params(4, 3)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

# TODO remove duplicated function `check_mempool_result` with mempool_accept.py
    def check_mempool_result(self, result_expected, *args, **kwargs):
        """Wrapper to check result of testmempoolaccept on node_0's mempool"""
        result_test = self.nodes[0].testmempoolaccept(*args, **kwargs)
        assert_equal(result_expected, result_test)
        assert_equal(self.nodes[0].getmempoolinfo()['size'], self.mempool_size)  # Must not change mempool state

    def set_sporks(self):
        spork_enabled = 0
        spork_disabled = 4070908800

        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", spork_enabled)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_3_INSTANTSEND_BLOCK_FILTERING", spork_disabled)
        self.nodes[0].sporkupdate("SPORK_2_INSTANTSEND_ENABLED", spork_disabled)
        self.wait_for_sporks_same()

    def run_test(self):
        node = self.nodes[0]

        self.activate_dip0027_assetlocks()
        self.set_sporks()

        self.mempool_size = 0
        assert_equal(node.getmempoolinfo()['size'], self.mempool_size)

        key = ECKey()
        key.generate()
        pubkey = key.get_pubkey().get_bytes()

        self.log.info("Testing asset lock...")
        coins = node.listunspent()
        coin = coins.pop()
        locked_1 = 10 * COIN + 141421
        asset_lock_tx = create_assetlock(node, coin, locked_1, pubkey)

        self.check_mempool_result(
            result_expected=[{'txid': asset_lock_tx.rehash(), 'allowed': True }],
            rawtxs=[asset_lock_tx.serialize().hex()],
        )
        assert_equal(get_credit_pool_amount(node), 0)
        txid_in_block = node.sendrawtransaction(hexstring=asset_lock_tx.serialize().hex(), maxfeerate=0)

        node.generate(13)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_1)

        # tx is mined, let's get blockhash
        self.log.info("Invalidate block with asset lock tx...")
        block_hash_1 = node.gettransaction(txid_in_block)['blockhash']
        for inode in self.nodes:
            inode.invalidateblock(block_hash_1)
        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), 0)
        self.log.info("Resubmit asset lock tx to new chain...")
        txid_in_block = node.sendrawtransaction(hexstring=asset_lock_tx.serialize().hex(), maxfeerate=0)
        node.generate(3)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_1)

        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), locked_1)
        self.log.info("Reconsider old blocks...")
        for inode in self.nodes:
            inode.reconsiderblock(block_hash_1)
        assert_equal(get_credit_pool_amount(node), locked_1)
        self.sync_all()

        self.log.info("Mine a quorum...")
        self.mine_quorum()
        node.generate(3)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), locked_1)

        self.log.info("Testing asset unlock...")
        asset_unlock_tx = create_assetunlock(node, self.mninfo, 101, COIN, pubkey)
        asset_unlock_tx_late = create_assetunlock(node, self.mninfo, 102, COIN, pubkey)
        asset_unlock_tx_too_late = create_assetunlock(node, self.mninfo, 103, COIN, pubkey)

        self.check_mempool_result(
            result_expected=[{'txid': asset_unlock_tx.rehash(), 'allowed': True }],
            rawtxs=[asset_unlock_tx.serialize().hex()],
        )

        asset_unlock_tx_payload = CAssetUnlockTx()
        asset_unlock_tx_payload.deserialize(BytesIO(asset_unlock_tx.vExtraPayload))

        assert_equal(asset_unlock_tx_payload.quorumHash, int(self.mninfo[0].node.quorum("selectquorum", llmq_type_test, 'e6c7a809d79f78ea85b72d5df7e9bd592aecf151e679d6e976b74f053a7f9056')["quorumHash"], 16))

        node.sendrawtransaction(hexstring=asset_unlock_tx.serialize().hex(), maxfeerate=0)
        node.generate(1)
        self.sync_all()
        try:
            node.sendrawtransaction(hexstring=asset_unlock_tx.serialize().hex(), maxfeerate=0)
            raise AssertionError("Transaction should not be mined: double copy")
        except JSONRPCException as e:
            assert "Transaction already in block chain" in e.error['message']

        self.log.info("Invalidate block with asset unlock tx...")
        block_asset_unlock = node.getbestblockhash()
        for inode in self.nodes:
            inode.invalidateblock(block_asset_unlock)
        assert_equal(get_credit_pool_amount(node), locked_1)
        # TODO: strange, fails if generate there new blocks
        #node.generate(3)
        #self.sync_all()
        for inode in self.nodes:
            inode.reconsiderblock(block_asset_unlock)
        assert_equal(get_credit_pool_amount(node), locked_1 - COIN)

        # mine next quorum, tx should be still accepted
        self.mine_quorum()
        self.check_mempool_result(
            result_expected=[{'txid': asset_unlock_tx_late.rehash(), 'allowed': True }],
            rawtxs=[asset_unlock_tx_late.serialize().hex()],
        )

        # two quorums later is too late
        self.mine_quorum()
        self.check_mempool_result(
            result_expected=[{'txid': asset_unlock_tx_too_late.rehash(), 'allowed': False, 'reject-reason' : '16: bad-assetunlock-too-late'}],
            rawtxs=[asset_unlock_tx_too_late.serialize().hex()],
        )

        node.generate(13)
        self.sync_all()

        assert_equal(get_credit_pool_amount(node), locked_1 - COIN)
        assert_equal(get_credit_pool_amount(node, block_hash_1), locked_1)

        # too big withdrawal should not be mined
        aset_unlock_tx_full = create_assetunlock(node, self.mninfo, 201, 1 + get_credit_pool_amount(node), pubkey)
        self.check_mempool_result(
            result_expected=[{'txid': aset_unlock_tx_full.rehash(), 'allowed': True }],
            rawtxs=[aset_unlock_tx_full.serialize().hex()],
        )

        txid_in_block = node.sendrawtransaction(hexstring=aset_unlock_tx_full.serialize().hex(), maxfeerate=0)
        node.generate(13)
        self.sync_all()
        try:
            node.gettransaction(txid_in_block)
            raise AssertionError("Transaction should not be mined")
        except JSONRPCException as e:
            assert "Invalid or non-wallet transaction id" in e.error['message']

        self.mempool_size += 1
        aset_unlock_tx_full = create_assetunlock(node, self.mninfo, 301, get_credit_pool_amount(node), pubkey)
        self.check_mempool_result(
            result_expected=[{'txid': aset_unlock_tx_full.rehash(), 'allowed': True }],
            rawtxs=[aset_unlock_tx_full.serialize().hex()],
        )

        txid_in_block = node.sendrawtransaction(hexstring=aset_unlock_tx_full.serialize().hex(), maxfeerate=0)
        node.generate(13)
        self.sync_all()
        assert_equal(get_credit_pool_amount(node), 0)

        # test withdrawal limits
        # fast-forward to next day to reset previous limits
        node.generate(576 + 1)
        self.sync_all()
        self.mine_quorum()
        total = get_credit_pool_amount(node)
        while total <= 20_000 * COIN:
            coin = coins.pop()
            to_lock = int(coin['amount'] * COIN) - tiny_amount
            total += to_lock
            tx = create_assetlock(node, coin, to_lock, pubkey)
            node.sendrawtransaction(hexstring=tx.serialize().hex(), maxfeerate=0)
        node.generate(1)
        self.sync_all()
        amount_to_withdraw = get_credit_pool_amount(node)
        print(f'total locked: {PA(amount_to_withdraw)}')
        assert_greater_than(amount_to_withdraw, 11_000 * COIN)
        amount_under_limit = amount_to_withdraw // 10
        amount = int(amount_under_limit * 0.95)
        index = 400

        # take most of limit by one big tx for faster testing
        asset_unlock_tx = create_assetunlock(node, self.mninfo, index, amount, pubkey)
        node.sendrawtransaction(hexstring=asset_unlock_tx.serialize().hex(), maxfeerate=0)
        node.generate(1)
        self.sync_all()
        while amount < amount_under_limit:
            next = COIN * 5
            amount += next
            index += 1
            asset_unlock_tx = create_assetunlock(node, self.mninfo, index, next, pubkey)
            node.sendrawtransaction(hexstring=asset_unlock_tx.serialize().hex(), maxfeerate=0)
        print(f"mempool: {node.getmempoolinfo()['size']}")
        node.generate(1)
        self.sync_all()
        print(f'trying to unlock: {PA(amount)}')
        print(f'expected to unlock no more than: {PA(amount_under_limit)}')
        print(f'new locked: {PA(get_credit_pool_amount(node))}')
        print(f'unlocked: {PA(total - get_credit_pool_amount(node))}')
        assert_greater_than(amount, amount_under_limit)
        assert_greater_than_or_equal(amount_under_limit, total - get_credit_pool_amount(node))
        assert_greater_than_or_equal(total-get_credit_pool_amount(node), amount_under_limit)
        assert_greater(total - get_credit_pool_amount(node), 1000)
        print("mempool:")
        print(self.nodes[0].getmempoolinfo()['size'])
        node.generate(100)
        # all tx should be dropped from mempool because new quorums
        node.generate(650)
        self.sync_all()
        print("mempool:")
        print(self.nodes[0].getmempoolinfo()['size'])
        print(node.getmempoolinfo())
        print(node.getrawmempool())
        print(node.getmempoolentry(node.getrawmempool()[0]))
        assert_equal(node.getmempoolinfo()['size'], 0)

            
if __name__ == '__main__':
    AssetLocksTest().main()
