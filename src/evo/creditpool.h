// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_EVO_CREDITPOOL_H
#define BITCOIN_EVO_CREDITPOOL_H

#include <coins.h>

#include <evo/assetlocktx.h>

#include <sync.h>
#include <threadsafety.h>

#include <map>

class CCreditPoolManager
{
private:
    CAmount prevLocked;
    CAmount sessionLocked{0};
    CAmount sessionUnlocked{0};
    CAmount sessionLimit;

    bool lock(const CTransaction& tx, CValidationState& state);

    bool unlock(const CTransaction& tx, CValidationState& state);

public:
    CCreditPoolManager(CAmount prevLocked = 0, CAmount latelyUnlocked = 0)
    : prevLocked(prevLocked)
    , sessionLimit(prevLocked)
    {
        if ((sessionLimit + latelyUnlocked > (prevLocked + latelyUnlocked) / 10) && (sessionLimit + latelyUnlocked > 1000 * COIN)) {
            sessionLimit = (latelyUnlocked + prevLocked) / 10 - latelyUnlocked;
            if (sessionLimit > prevLocked) sessionLimit = prevLocked;
        }
        if (prevLocked || latelyUnlocked) {
//            std::cerr << "new credit pool manager: " << prevLocked << ' ' << latelyUnlocked << '\n' << sessionLimit << ' ' << '\n';
        }
    }

    ~CCreditPoolManager() = default;

    // This function should be called for each Asset Lock/Unlock tx
    // to change amount of credit pool
    bool processTransaction(const CTransaction& tx, CValidationState& state, CBlockIndex* pindexPrev);

    CAmount getTotalLocked() const;
};

#endif
