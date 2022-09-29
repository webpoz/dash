#!/usr/bin/env python3

# Copyright (c) 2022 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import time
import hashlib

from io import BytesIO
from decimal import Decimal
from test_framework.authproxy import JSONRPCException

from test_framework.test_framework import DashTestFramework
from test_framework.util import (
        connect_nodes,
        assert_equal,
        wait_until,
    )

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

llmq_type_test = 100

def create_assetlock(node, coin, amount, pubkey):
    inputs = [CTxIn(COutPoint(int(coin["txid"], 16), coin["vout"]))]

    credit_outputs = CTxOut(amount, CScript([OP_DUP, OP_HASH160, hash160(pubkey), OP_EQUALVERIFY, OP_CHECKSIG]))

    lockTx_payload = CAssetLockTx(1, 0, [credit_outputs])

    fee = Decimal(0.00070000)
    remaining = int(COIN * coin['amount']) - int(COIN * fee) - credit_outputs.nValue

    tx_output_ret = CTxOut(credit_outputs.nValue, CScript([OP_RETURN, b""]))
    tx_output = CTxOut(remaining, CScript([pubkey, OP_CHECKSIG]))

    lock_tx = CTransaction()
    lock_tx.vin = inputs
    lock_tx.vout = [tx_output, tx_output_ret]
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

    fee = int(0.00000700 * COIN)
    tx_output = CTxOut(int(withdrawal) - fee, CScript([pubkey, OP_CHECKSIG]))

    # request ID = sha256("plwdtx", index)
    sha256 = hashlib.sha256()
    sha256.update(("plwdtx" + str(index)).encode())
    id = sha256.digest()[::-1].hex()

    height = node.getblockcount()
    quorumHash = mninfo[0].node.quorum("selectquorum", llmq_type_test, id)["quorumHash"]
    unlockTx_payload = CAssetUnlockTx(
        version = 1,
        index = index,
        fee = fee,
        requestedHeight = height,
        quorumHash = int(quorumHash, 16),
        quorumSig = b'\00' * 96)

    unlock_tx = CTransaction()
    unlock_tx.vin = []
    unlock_tx.vout = [tx_output]
    unlock_tx.nVersion = 3
    unlock_tx.nType = 9 # asset unlock type
    unlock_tx.vExtraPayload = unlockTx_payload.serialize()

    unlock_tx.calc_sha256()
    msgHash = format(unlock_tx.sha256, '064x')

    for mn in mninfo:
        mn.node.quorum("sign", llmq_type_test, id, msgHash)

    wait_for_sigs(mninfo, id, msgHash, 5)

    recsig = mninfo[0].node.quorum("getrecsig", llmq_type_test, id, msgHash)

    unlockTx_payload.quorumSig = bytearray.fromhex(recsig["sig"])
    unlock_tx.vExtraPayload = unlockTx_payload.serialize()
    return unlock_tx

def get_credit_pool(node, block_hash = None):
    if not block_hash:
        block_hash = node.getbestblockhash()
    block = node.getblock(block_hash)
    return int(COIN * block['cbTx']['assetLockedAmount'])

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

    def run_test(self):
        node = self.nodes[0]

        self.activate_dip0027_assetlocks()

        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", 0)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", 4070908800)
        self.nodes[0].sporkupdate("SPORK_3_INSTANTSEND_BLOCK_FILTERING", 4070908800)
        self.nodes[0].sporkupdate("SPORK_2_INSTANTSEND_ENABLED", 4070908800)
        self.wait_for_sporks_same()

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
        assert_equal(get_credit_pool(node), 0)
        txid_in_block = node.sendrawtransaction(hexstring=asset_lock_tx.serialize().hex(), maxfeerate=0)

        node.generate(13)
        self.sync_all()

        # tx is mined, let's get blockhash
        block_hash_1 = node.gettransaction(txid_in_block)['blockhash']
        self.log.info(block_hash_1)

        assert_equal(get_credit_pool(node), locked_1)

        self.log.info("Mining a quorum...")
        self.mine_quorum()
        node.generate(3)
        self.sync_all()


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

        assert_equal(get_credit_pool(node), locked_1 - COIN)
        assert_equal(get_credit_pool(node, block_hash_1), locked_1)

        # too big withdrawal should not be mined
        aset_unlock_tx_full = create_assetunlock(node, self.mninfo, 201, 1 + get_credit_pool(node), pubkey)
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
        aset_unlock_tx_full = create_assetunlock(node, self.mninfo, 301, get_credit_pool(node), pubkey)
        self.check_mempool_result(
            result_expected=[{'txid': aset_unlock_tx_full.rehash(), 'allowed': True }],
            rawtxs=[aset_unlock_tx_full.serialize().hex()],
        )

        txid_in_block = node.sendrawtransaction(hexstring=aset_unlock_tx_full.serialize().hex(), maxfeerate=0)
        node.generate(13)
        self.sync_all()
        assert_equal(get_credit_pool(node), 0)

if __name__ == '__main__':
    AssetLocksTest().main()
