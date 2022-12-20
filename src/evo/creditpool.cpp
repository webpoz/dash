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

static const std::string DB_CREDITPOOL_SNAPSHOT = "cpm_S";

std::unique_ptr<CCreditPoolManager> creditPoolManager;

static bool getDataFromUnlockTx(const CTransaction& tx, CAmount& toUnlock, uint64_t& index, CValidationState& state) {
    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-payload");
    }

    index = assetUnlockTx.getIndex();
    toUnlock = assetUnlockTx.getFee();
    for (const CTxOut& txout : tx.vout) {
        if (txout.nValue < 0) {
            return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-negative-amount");
        }
        toUnlock += txout.nValue;
    }
    return true;
}

// throws exception if anything went wrong
static void getDataFromUnlockTxes(const std::vector<CTransactionRef>& vtx, CAmount& totalUnlocked, std::set<uint64_t>& indexes) {
    for (CTransactionRef tx : vtx) {
        if (tx->nVersion != 3 || tx->nType != TRANSACTION_ASSET_UNLOCK) continue;

        CAmount unlocked{0};
        CValidationState state;
        uint64_t index{0};
        if (!getDataFromUnlockTx(*tx, unlocked, index, state)) {
            throw std::runtime_error(strprintf("%s: getCreditPool failed: %s", __func__, FormatStateMessage(state)));
        }
        totalUnlocked += unlocked;
        indexes.insert(index);
    }
}

bool SkipSet::add(uint64_t value) {
    assert(!contains(value));

    if (auto it = skipped.find(value); it != skipped.end()) {
        skipped.erase(it);
    } else {
        assert(right <= value);

        if (capacity() + value - right > capacity_limit) {
            LogPrintf("SkipSet::add failed due to capacity exceeded: requested %lld to %lld while limit is %lld\n",
                    value - right, capacity(), capacity_limit);
            return false;
        }
        for (uint64_t index = right; index < value; ++index) {
            bool insert_ret = skipped.insert(index).second;
            assert(insert_ret);
        }
        right = value + 1;
    }
    return true;
}

bool SkipSet::canBeAdded(uint64_t value, CValidationState& state) const {
    if (contains(value)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-duplicated-index");
    }
    if (skipped.find(value) != skipped.end()) return true;

    if (capacity() + value - right > capacity_limit) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-getcbforblock-index-exceed");
    }

    return true;
}

bool SkipSet::contains(uint64_t value) const {
    if (right <= value) return false;
    return skipped.find(value) == skipped.end();
}

std::string CreditPoolCb::ToString() const {
    return strprintf("CreditPoolCb(locked=%lld,currentLimit=%lld,nIndexes=%lld)",
            locked, currentLimit, indexes.size());
}

std::optional<CreditPoolCb> CCreditPoolManager::getFromCache(const uint256& block_hash, int height) {
    CreditPoolCb pool;
    {
        LOCK(cs_cache);
        if (creditPoolCache.get(block_hash, pool)) {
            return pool;
        }
    }
    if (height % DISK_SNAPSHOT_PERIOD == 0) {
        if (evoDb.Read(std::make_pair(DB_CREDITPOOL_SNAPSHOT, block_hash), pool)) {
            LOCK(cs_cache);
            creditPoolCache.insert(block_hash, pool);
            return pool;
        }
    }
    return std::nullopt;
}

void CCreditPoolManager::addToCache(const uint256& block_hash, int height, const CreditPoolCb &pool) {
    {
        LOCK(cs_cache);
        creditPoolCache.insert(block_hash, pool);
    }
    if (height % DISK_SNAPSHOT_PERIOD == 0) {
        evoDb.Write(std::make_pair(DB_CREDITPOOL_SNAPSHOT, block_hash), pool);
    }
}

static std::optional<CBlock> getBlockForCreditPool(const CBlockIndex *block_index, const Consensus::Params& consensusParams) {
    CBlock block;
    if (!ReadBlockFromDisk(block, block_index, consensusParams)) {
        throw std::runtime_error("failed-getcbforblock-read");
    }
    // Should not fail if V19 (DIP0027) are active but happens for Unit Tests
    if (block.vtx[0]->nVersion != 3) {
        return std::nullopt;
    }
    assert(!block.vtx.empty());
    assert(block.vtx[0]->nVersion == 3);
    assert(!block.vtx[0]->vExtraPayload.empty());

    return block;
}

CreditPoolCb CCreditPoolManager::getCreditPool(const CBlockIndex* block_index, const Consensus::Params& consensusParams)
{
    bool isDIP0027AssetLocksActive = llmq::utils::IsV19Active(block_index);
    if (!isDIP0027AssetLocksActive) {
        return {};
    }

    uint256 block_hash = block_index->GetBlockHash();
    int block_height = block_index->nHeight;
    {
        auto pool = getFromCache(block_hash, block_height);
        if (pool) { return pool.value(); }
    }

    CreditPoolCb prev = getCreditPool(block_index->pprev, consensusParams);

    std::optional<CBlock> block = getBlockForCreditPool(block_index, consensusParams);
    if (!block) {
        assert(prev.locked == 0);
        assert(prev.indexes.size() == 0);

        CreditPoolCb emptyPool;
        addToCache(block_hash, block_height, emptyPool);
        return emptyPool;
    }
    CAmount locked{0};
    {
        CCbTx cbTx;
        if (!GetTxPayload(block->vtx[0]->vExtraPayload, cbTx)) {
            throw std::runtime_error(strprintf("%s: failed-getcreditpool-cbtx-payload", __func__));
        }
        locked = cbTx.assetLockedAmount;
    }
    CAmount blockUnlocked{0};
    std::set<uint64_t> new_indexes;
    getDataFromUnlockTxes(block->vtx, blockUnlocked, new_indexes);
    SkipSet indexes{prev.indexes};
    if (std::any_of(new_indexes.begin(), new_indexes.end(), [&](const uint64_t index) { return !indexes.add(index); })) {
        throw std::runtime_error(strprintf("%s: failed-getcreditpool-index-exceed", __func__));
    }

    const CBlockIndex* distant_block_index = block_index;
    for (size_t i = 0; i < CCreditPoolManager::LimitBlocksToTrace; ++i) {
        distant_block_index = distant_block_index->pprev;
        if (distant_block_index == nullptr) break;
    }
    CAmount distantUnlocked{0};
    if (distant_block_index) {
        std::optional<CBlock> distant_block = getBlockForCreditPool(distant_block_index, consensusParams);
        if (distant_block) {
            std::set<uint64_t> indexes_tmp;
            getDataFromUnlockTxes(distant_block->vtx, distantUnlocked, indexes_tmp);
        }
    }

    // # max(100, min(.10 * assetlockpool, 1000))
    CAmount currentLimit = locked;
    CAmount latelyUnlocked = prev.latelyUnlocked + blockUnlocked - distantUnlocked;
    if (currentLimit + latelyUnlocked > LimitAmountLow) {
        currentLimit = std::max(LimitAmountLow, locked / 10) - latelyUnlocked;
        if (currentLimit < 0) currentLimit = 0;
    }
    currentLimit = std::min(currentLimit, LimitAmountHigh - latelyUnlocked);

    assert(currentLimit >= 0);

    if (currentLimit || latelyUnlocked || locked) {
        LogPrintf("getCreditPool asset unlock limits on height: %d locked: %d.%08d limit: %d.%08d previous: %d.%08d\n", block_index->nHeight, locked / COIN, locked % COIN,
               currentLimit / COIN, currentLimit % COIN,
               latelyUnlocked / COIN, latelyUnlocked % COIN);
    }

    CreditPoolCb pool{locked, currentLimit, latelyUnlocked, indexes};
    addToCache(block_hash, block_height, pool);
    return pool;
}


CCreditPoolManager::CCreditPoolManager(CEvoDB& _evoDb)
: evoDb(_evoDb)
{
}

CreditPoolCbDiff::CreditPoolCbDiff(const CreditPoolCb& starter, const CBlockIndex *pindex, const Consensus::Params& consensusParams)
: pool(starter)
, pindex(pindex)
{
    assert(pindex);
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

        sessionLocked += txout.nValue;
        return true;
    }

    return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-lock-invalid");
}

bool CreditPoolCbDiff::unlock(const CTransaction& tx, CValidationState& state)
{
    uint64_t index{0};
    CAmount toUnlock{0};
    if (!getDataFromUnlockTx(tx, toUnlock, index, state)) {
        // state is set up inside getDataFromUnlockTx
        return false;
    }

    if (sessionUnlocked + toUnlock > pool.currentLimit) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unloock-too-much");
    }

    if (!pool.indexes.canBeAdded(index, state)) {
        return false;
    }
    if (newIndexes.count(index)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-duplicated-index");
    }

    newIndexes.insert(index);
    sessionUnlocked += toUnlock;
    return true;
}

bool CreditPoolCbDiff::processTransaction(const CTransaction& tx, CValidationState& state) {
    if (tx.nVersion != 3) return true;
    if (tx.nType != TRANSACTION_ASSET_LOCK && tx.nType != TRANSACTION_ASSET_UNLOCK) return true;

    if (auto maybeError = CheckAssetLockUnlockTx(tx, pindex, this->pool); maybeError.did_err) {
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
