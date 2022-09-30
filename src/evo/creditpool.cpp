// Copyright (c) 2022 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <evo/creditpool.h>

#include <evo/assetlocktx.h>

#include <logging.h>

#include <exception>
#include <memory>

static CAmount getLockedAmount(const CTransaction& tx) {
    for (const CTxOut& txout : tx.vout) {
        const CScript& script = txout.scriptPubKey;
        if (script.empty() || script[0] != OP_RETURN) continue;

        return txout.nValue;
    }
    throw std::runtime_error("Never should happen: Asset Lock without OP_RETURN");
}

bool CCreditPoolManager::lock(const CTransaction& tx, CValidationState& state)
{
    CAssetLockPayload assetLockTx;
    if (!GetTxPayload(tx, assetLockTx)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-lock-payload");
    }

    totalLocked += getLockedAmount(tx);

    return true;
}

static bool getAmountToUnlock(const CTransaction& tx, CAmount fee, CAmount& txUnlocked) {
    txUnlocked = fee;
    for (const CTxOut& txout : tx.vout) {
//        const CScript& script = txout.scriptPubKey;
        if (txout.nValue < 0) return false;
        txUnlocked += txout.nValue;
    }

    return true;
}

bool CCreditPoolManager::unlock(const CTransaction& tx, CValidationState& state)
{
    CAssetUnlockPayload assetUnlockTx;
    if (!GetTxPayload(tx, assetUnlockTx)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-payload");
    }
    CAmount toUnlock;
    if (!getAmountToUnlock(tx, assetUnlockTx.getFee(), toUnlock)) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unlock-amount");
    }

    // For now there's no proper limits of withdrawal
    CAmount limit = std::min(totalLocked, 10'000 * COIN);
    if (toUnlock > limit) {
        return state.Invalid(ValidationInvalidReason::CONSENSUS, false, REJECT_INVALID, "failed-creditpool-unloock-too-much");
    }

    totalLocked -= toUnlock;
    return true;
}

bool CCreditPoolManager::processTransaction(const CTransaction& tx, CValidationState& state) {
    if (tx.nVersion != 3) return true;

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


CAmount CCreditPoolManager::getTotalLocked() const
{
    return totalLocked;
}
