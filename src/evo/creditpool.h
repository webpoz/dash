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

// In this data structure we keep all indexes memory efficient
// So far as CreditPoolCb is built only in direction from parent block to child
// there's no need to remove elements from SkipSet ever, only add them
struct SkipSet {
    SERIALIZE_METHODS(SkipSet, obj)
    {
        READWRITE(obj.right);
        READWRITE(obj.skipped);
    }
    [[nodiscard]] bool add(int64_t value);

    bool contains(int64_t value) const;

    size_t size() const {
        return right - skipped.size();
    }
    size_t capacity() const {
        return skipped.size();
    }
private:
    std::unordered_set<int64_t> skipped;
    int64_t right{0};
};

struct CreditPoolCb {
    CAmount locked{0};

    // needs for logic of limits of unlocks
    CAmount currentLimit{0};
    CAmount latelyUnlocked{0};
    SkipSet indexes{};

    SERIALIZE_METHODS(CreditPoolCb, obj)
    {
        READWRITE(
            obj.locked,
            obj.currentLimit,
            obj.latelyUnlocked,
            obj.indexes
        );
    }
};

struct CreditPoolCbDiff {
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    const CBlockIndex *pindex{nullptr};
    CreditPoolCbDiff(const CreditPoolCb& starter, const CBlockIndex *pindex, const Consensus::Params& consensusParams);

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const {
        return pool.locked + sessionLocked - sessionUnlocked;
    }
private:
    CreditPoolCb pool;
};

class CCreditPoolManager
{
private:
    static constexpr size_t CreditPoolCacheSize = 1000;
    CCriticalSection cs_cache;
    unordered_lru_cache<uint256, CreditPoolCb, StaticSaltedHasher> creditPoolCache GUARDED_BY(cs_cache) {CreditPoolCacheSize};

    CEvoDB& evoDb;

    static constexpr int DISK_SNAPSHOT_PERIOD = 576; // once per day
private:
    std::optional<CreditPoolCb> getFromCache(const uint256& block_hash, int height);
    void addToCache(const uint256& block_hash, int height, CreditPoolCb pool);

public:

    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmountLow = 100 * COIN;
    static constexpr CAmount LimitAmountHigh = 1000 * COIN;
public:
    explicit CCreditPoolManager(CEvoDB& _evoDb);

    ~CCreditPoolManager() = default;

    CreditPoolCb getCreditPool(const CBlockIndex* block, const Consensus::Params& consensusParams);
};

extern std::unique_ptr<CCreditPoolManager> creditPoolManager;

#endif
