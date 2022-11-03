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

#include <deque>
#include <map>

#include <saltedhasher.h>
#include <unordered_lru_cache.h>

class CBlockIndex;
namespace Consensus
{
    class Params;
}

// TODO knst save data like a range
struct SkipSet {
    std::set<int64_t> used;

    void add(int64_t value) {
        assert(!exists(value));
        used.insert(value);
    }
    void remove(int64_t value) {
        assert(exists(value));
        used.erase(used.find(value));
    }
    bool exists(int64_t value) {
        return used.find(value) != used.end();
    }
    size_t size() const {
        return used.size();
    }
/*
   std::set<std::pair<int64_t, int64_t>> ranges;

    void add(int64_t value) {
        assert(!exists(value));

        lower_bound(
        ranges.insert({value, value});

    }
    void remove(int64_t value) {
        assert(exist(value));

    }


    bool exists(int64_t value) {
    }
*/
};

struct CreditPoolCb {
    // TODO KNST  make const ?
    CAmount locked;
//    CAmount latelyUnlocked;
    CAmount totalUnlocked;
    SkipSet indexes;

    // -----
//    CBlockIndex* pindexPrev;
    const CBlockIndex* pindex;

    /*
    CAmount getTotalLocked() const {
        return locked + sessionLocked - sessionUnlocked;
    }
    */

//    static CreditPoolCb GetCbForBlock(const CBlockIndex* block_index, const Consensus::Params& consensusParams);
};

struct CreditPoolCbDiff {
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    CAmount sessionLimit{0}; // prevLocked

    CreditPoolCbDiff(const CreditPoolCb& starter, const Consensus::Params& consensusParams)
    : pool(starter) {
        initSessionLimit(consensusParams);
    }

    void initSessionLimit(const Consensus::Params& consensusParams);

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const {
        LogPrintf("pool-status %lld %lld %lld\n", pool.locked, sessionLocked, sessionUnlocked);
        return pool.locked + sessionLocked - sessionUnlocked;
    }
private:
    CreditPoolCb pool;
};

class CCreditPoolManager
{
private:

    static constexpr size_t CreditPoolCacheSize = 1000;
    static unordered_lru_cache<uint256, CreditPoolCb, StaticSaltedHasher> creditPoolCache GUARDED_BY(cs_cache);

    CEvoDB& evoDb;
/*
    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);
*/
public:
    // TODO knst
    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmountLow = 100 * COIN;
    static constexpr CAmount LimitAmountHigh = 1000 * COIN;
public:
    CCreditPoolManager(CEvoDB& _evoDb);

    ~CCreditPoolManager() = default;

    void DoMaintenance() {
        // TODO knst
    }
    /*
    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);
*/
    CreditPoolCb getCreditPool(CBlockIndex* block, const Consensus::Params& consensusParams) const;
};

extern std::unique_ptr<CCreditPoolManager> creditPoolManager;

#endif
