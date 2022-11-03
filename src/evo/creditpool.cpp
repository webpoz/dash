// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/creditpool.h>

#include <evo/assetlocktx.h>
#include <evo/cbtx.h>

#include <llmq/utils.h>

#include <chain.h>
#include <logging.h>
#include <util/validation.h>
#include <validation.h>

#include <algorithm>
#include <exception>
#include <memory>

static const std::string DB_LIST_SNAPSHOT = "cpm_S";
static const std::string DB_LIST_DIFF = "cpm_D";

std::unique_ptr<CCreditPoolManager> creditPoolManager;

unordered_lru_cache<uint256, CreditPoolCb, StaticSaltedHasher> CCreditPoolManager::creditPoolCache(CreditPoolCacheSize);

static bool getAmountToUnlock(const CTransaction& tx, CAmount& toUnlock, int64_t& index, CValidationState& state) {
    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-payload");
    }

    index = assetUnlockTx.getIndex();
    LogPrintf("get-amount-to-unlock fee: %lld\n", assetUnlockTx.getFee());
    toUnlock = assetUnlockTx.getFee();
    for (const CTxOut& txout : tx.vout) {
        if (txout.nValue < 0) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-negative-amount");
        }
        toUnlock += txout.nValue;
        LogPrintf("get-amount-to-unlock next: %lld\n", txout.nValue);
    }
    LogPrintf("get-amount-to-unlock total: %lld\n", toUnlock);
    return true;
}

namespace {
CCriticalSection cs_cache;

} // anonymous namespace

CreditPoolCb CCreditPoolManager::getCreditPool(CBlockIndex* block_index, const Consensus::Params& consensusParams) const
{
    // TODO knst
    // latelyUnlocked -> replace to sessionUnlocked
    // sum up throught 576 blocks; can't keep total unlocked because CAmount will be over-flowed very soon
    // keep in cache - sessionUnlocked; everything would be happy


    bool fDIP0027AssetLocksActive_context = llmq::utils::IsDIP0027AssetLocksActive(block_index);
    LogPrintf("dip status %d %d\n", fDIP0027AssetLocksActive_context, block_index->nHeight);
    if (!fDIP0027AssetLocksActive_context) {
        LogPrintf("getCreditPool case-1\n");
        return {0, 0, {}, block_index};
    }

    uint256 block_hash = block_index->GetBlockHash();

    {
        LOCK(cs_cache);
        CreditPoolCb pool{0, 0, {}, block_index};
        if (creditPoolCache.get(block_hash, pool)) {
            LogPrintf("getCreditPool case-2\n");
            return pool;
        }
    }
    CreditPoolCb prev = getCreditPool(block_index->pprev, consensusParams);
if (true) {
    CBlock block;
    if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
        throw std::runtime_error("failed-getcbforblock-read");
    }
    assert(!block.vtx.empty());
    if (block.vtx[0]->vExtraPayload.empty()) {
        LogPrintf("getCreditPool payload-empty debug chain height %d whlie peypeyload on %d\n",
                ::ChainActive().Tip()->nHeight, block_index->nHeight);
    }
    if (block.vtx[0]->nVersion < 2) {
        LogPrintf("getCreditPool case-3\n");
        LogPrintf("getCreditPool vtx-version debug chain height %d whlie peypeyload on %d\n",
                ::ChainActive().Tip()->nHeight, block_index->nHeight);
        throw std::runtime_error("wtf hoyya vtx not version 3");
        return {0, 0, {}, block_index};
    }
    // TODO knst wtf why it is empty even DIP0008 active? ask pasta
    if (block.vtx[0]->vExtraPayload.empty()) {
        return {0, 0, {}, block_index};
    }
    assert(!block.vtx[0]->vExtraPayload.empty());

    CCbTx cbTx;
    if (!GetTxPayload(block.vtx[0]->vExtraPayload, cbTx)) {
        LogPrintf("getCreditPool case-4\n");
        throw std::runtime_error("failed-getcbforblock-cbtx-payload");
    }

    CAmount blockUnlocked{0};
    SkipSet indexes;
    for (CTransactionRef tx : block.vtx) {
        if (tx->nVersion != 3 || tx->nType != TRANSACTION_ASSET_UNLOCK) continue;

        CAmount unlocked{0};
        CValidationState state;
        int64_t index;
        if (!getAmountToUnlock(*tx, unlocked, index, state)) {
            throw std::runtime_error(strprintf("%s: getCreditPool failed: %s", __func__, FormatStateMessage(state)));
        }
        blockUnlocked += unlocked;
        indexes.add(index);
    }
    LogPrintf("getCreditPool unlocked in block: %lld\n", blockUnlocked);

    CreditPoolCb pool{cbTx.assetLockedAmount, prev.totalUnlocked + blockUnlocked, indexes, block_index};
    {
        LOCK(cs_cache);
        creditPoolCache.insert(block_hash, pool);
    }
    LogPrintf("getCreditPool case-6\n");
    return pool;
} else {
        CreditPoolCb pool{0, 0, {}, block_index};
        LOCK(cs_cache);
        creditPoolCache.insert(block_hash, pool);
        LogPrintf("getCreditPool case-7\n");
        return pool;
}
}


CCreditPoolManager::CCreditPoolManager(CEvoDB& _evoDb)
: evoDb(_evoDb)
{
}

void CreditPoolCbDiff::initSessionLimit(const Consensus::Params& consensusParams) {
    // validate here to be sure init
    assert(pool.pindex);
    const CAmount prevLocked = pool.locked;
    // KNST incorrect temporary
    const CAmount latelyUnlocked = pool.totalUnlocked;
    const CBlockIndex * other_block = pool.pindex;
    for (size_t i = 0; i < CCreditPoolManager::LimitBlocksToTrace; ++i) {
        other_block = other_block->pprev;
        if (other_block == nullptr) break;
    }
    if (other_block) {
        // TODO knst FIXME should not be called from here
        latelyUnlocked -= getCreditPool(other_block, Params().GetConsensus());
    }
//    const CAmount latelyUnlocked = pool.latelyUnlocked;

    sessionLimit = prevLocked;

    // # max(100, min(.10 * assetlockpool, 1000))
    if ((sessionLimit + latelyUnlocked > (prevLocked + latelyUnlocked) / 10) && (sessionLimit + latelyUnlocked > CCreditPoolManager::LimitAmountLow)) {
        sessionLimit = std::max<CAmount>(0, (latelyUnlocked + prevLocked) / 10 - latelyUnlocked);
        if (sessionLimit > prevLocked) sessionLimit = prevLocked;
    }
    if (sessionLimit + latelyUnlocked > CCreditPoolManager::LimitAmountHigh) {
        sessionLimit = CCreditPoolManager::LimitAmountHigh - latelyUnlocked;
    }

    if (prevLocked || latelyUnlocked || sessionLimit) {
        LogPrintf("CreditPoolCb init on height %d: %d.%08d %d.%08d limited by %d.%08d\n", pool.pindex->nHeight, prevLocked / COIN, prevLocked % COIN,
               latelyUnlocked / COIN, latelyUnlocked % COIN,
               sessionLimit / COIN, sessionLimit % COIN);
    }
}


bool CreditPoolCbDiff::lock(const CTransaction& tx, CValidationState& state)
{
    CAssetLockPayload assetLockTx;
    if (!GetTxPayload(tx, assetLockTx)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-lock-payload");
    }

    for (const CTxOut& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;
        if (script.empty() || script[0] != OP_RETURN) continue;

        LogPrintf("pool-status change session locked %lld + %lld", sessionLocked, txout.nValue);
        sessionLocked += txout.nValue;
        LogPrintf(" = %lld\n", sessionLocked);
        return true;
    }

    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-lock-invalid");
}

bool CreditPoolCbDiff::unlock(const CTransaction& tx, CValidationState& state)
{
    int64_t index;
    CAmount toUnlock{0};
    if (!getAmountToUnlock(tx, toUnlock, index, state)) {
        // state is set up inside getAmountToUnlock
        return false;
    }

    if (pool.indexes.exists(index)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-duplicated-index");
    }
    pool.indexes.add(index);
    LogPrintf("pool-status trying to unlock %lld + %lld while limit %lld\n",
            sessionUnlocked, toUnlock, sessionLimit);
    if (sessionUnlocked + toUnlock > sessionLimit ) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unloock-too-much");
    }

    LogPrintf("pool-status change session unlocked %lld + %lld", sessionUnlocked, toUnlock);
    sessionUnlocked += toUnlock;
    LogPrintf(" = %lld\n", sessionUnlocked);
    return true;
}

bool CreditPoolCbDiff::processTransaction(const CTransaction& tx, CValidationState& state) {
    assert(pool.pindex);
    if (tx.nVersion != 3) return true;
    if (tx.nType != TRANSACTION_ASSET_LOCK && tx.nType != TRANSACTION_ASSET_UNLOCK) return true;

    if (auto maybeError = CheckAssetLockUnlockTx(tx, pool.pindex); maybeError.did_err) {
        return state.Invalid(maybeError.reason, false, REJECT_INVALID, std::string(maybeError.error_str));
    }

    try {
        switch (tx.nType) {
        case TRANSACTION_ASSET_LOCK:
            return lock(tx, state);
        case TRANSACTION_ASSET_UNLOCK:
            return unlock(tx, state);
        default:
            return true;
        }
    } catch (const std::exception& e) {
        LogPrintf("%s -- failed: %s\n", __func__, e.what());
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-procassetlocksinblock");
    }
}
