// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>
#include <evo/evodb.h>

#include <sync.h>
#include <threadsafety.h>

#include <optional>
#include <unordered_set>

#include <saltedhasher.h>
#include <unordered_lru_cache.h>

class CBlockIndex;
namespace Consensus
{
    class Params;
}

// This datastructure keeps efficiently all indexes and have a strict limit for used memory
// So far as CCreditPool is built only in direction from parent block to child
// there's no need to remove elements from SkipSet ever, only add them
class SkipSet {
private:
    std::unordered_set<uint64_t> skipped;
    uint64_t right{0};
    size_t capacity_limit;
public:
    explicit SkipSet(size_t capacity_limit = 10'000) :
        capacity_limit(capacity_limit)
    {}

    [[nodiscard]] bool add(uint64_t value);

    bool canBeAdded(uint64_t value, CValidationState& state) const;

    bool contains(uint64_t value) const;

    size_t size() const {
        return right - skipped.size();
    }
    size_t capacity() const {
        return skipped.size();
    }

    SERIALIZE_METHODS(SkipSet, obj)
    {
        READWRITE(obj.right);
        READWRITE(obj.skipped);
    }
};

struct CCreditPool {
    CAmount locked{0};

    // needs for logic of limits of unlocks
    CAmount currentLimit{0};
    CAmount latelyUnlocked{0};
    SkipSet indexes{};

    std::string ToString() const;

    SERIALIZE_METHODS(CCreditPool, obj)
    {
        READWRITE(
            obj.locked,
            obj.currentLimit,
            obj.latelyUnlocked,
            obj.indexes
        );
    }
};

// The class CCreditPoolDiff is used only during mining a new block to determine
// which `Asset Unlock` transactions can be included accordingly to the Credit Pool limits
// These extra class is needed for temporary storage of new values `lockedAmount` and `indexes`
// while limits should stay remained and depends only on previous block
class CCreditPoolDiff {
private:
    const CCreditPool pool;
    std::unordered_set<int64_t> newIndexes;

    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    const CBlockIndex *pindex{nullptr};
public:
    explicit CCreditPoolDiff(const CCreditPool& starter, const CBlockIndex *pindex, const Consensus::Params& consensusParams);

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const {
        return pool.locked + sessionLocked - sessionUnlocked;
    }

private:
    bool lock(const CTransaction& tx, CValidationState& state);
    bool unlock(const CTransaction& tx, CValidationState& state);
};

class CCreditPoolManager
{
private:
    static constexpr size_t CreditPoolCacheSize = 1000;
    CCriticalSection cs_cache;
    unordered_lru_cache<uint256, CCreditPool, StaticSaltedHasher> creditPoolCache GUARDED_BY(cs_cache) {CreditPoolCacheSize};

    CEvoDB& evoDb;

    static constexpr int DISK_SNAPSHOT_PERIOD = 576; // once per day

public:
    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmountLow = 100 * COIN;
    static constexpr CAmount LimitAmountHigh = 1000 * COIN;

    explicit CCreditPoolManager(CEvoDB& _evoDb);

    ~CCreditPoolManager() = default;

    // getCreditPOol throws an exception if something went wrong
    CCreditPool getCreditPool(const CBlockIndex* block, const Consensus::Params& consensusParams);

private:
    std::optional<CCreditPool> getFromCache(const uint256& block_hash, int height);
    void addToCache(const uint256& block_hash, int height, const CCreditPool& pool);
};

extern std::unique_ptr<CCreditPoolManager> creditPoolManager;

#endif
