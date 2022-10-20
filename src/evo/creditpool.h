// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>

#include <saltedhasher.h>
#include <sync.h>
#include <threadsafety.h>

#include <unordered_map>

class CBlockIndex;
namespace Consensus
{
    class Params;
}

class CCreditPoolManager
{
private:
    CBlockIndex* pindexPrev;

    CAmount prevLocked{0};
    CAmount sessionLimit{0};
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};

    std::unordered_map<uint256, CTransactionRef, StaticSaltedHasher> toDelete;

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

    static constexpr int LimitBlocksToTrace = 576;
    static constexpr CAmount LimitAmount = 1000 * COIN;
public:
    CCreditPoolManager(CBlockIndex* pindexPrev, const Consensus::Params& consensusParams);

    ~CCreditPoolManager() = default;

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const;

    const std::unordered_map<uint256, CTransactionRef, StaticSaltedHasher> getExpiryUnlocks() { return toDelete; }
};

#endif
