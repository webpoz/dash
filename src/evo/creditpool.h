// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>

#include <sync.h>
#include <threadsafety.h>

#include <logging.h>
#include <map>
#include <chain.h>

class CCreditPoolManager
{
private:
    CAmount prevLocked;
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};
    CAmount sessionLimit;

    CBlockIndex* pindexPrev;

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

public:
    CCreditPoolManager(CBlockIndex* pindexPrev, CAmount prevLocked = 0, CAmount latelyUnlocked = 0)
    : prevLocked(prevLocked)
    , sessionLimit(prevLocked)
    , pindexPrev(pindexPrev)
    {
        if ((sessionLimit + latelyUnlocked > (prevLocked + latelyUnlocked) / 10) && (sessionLimit + latelyUnlocked > 1000 * COIN)) {
            sessionLimit = std::max<CAmount>(0, (latelyUnlocked + prevLocked) / 10 - latelyUnlocked);
            if (sessionLimit > prevLocked) sessionLimit = prevLocked;
        }
        if (prevLocked || latelyUnlocked || sessionLimit) {
            LogPrintf("CreditPoolManager init on height %d: %d.%08d %d.%08d limited by %d.%08d\n", pindexPrev->nHeight, prevLocked / COIN, prevLocked % COIN,
                   latelyUnlocked / COIN, latelyUnlocked % COIN, 
                   sessionLimit / COIN, sessionLimit % COIN);
        }
    }

    ~CCreditPoolManager() = default;

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state);

    CAmount getTotalLocked() const;
};

#endif
