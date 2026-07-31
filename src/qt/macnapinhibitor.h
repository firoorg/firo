// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_MACNAPINHIBITOR_H
#define BITCOIN_QT_MACNAPINHIBITOR_H

/** Prevents macOS "App Nap" from throttling timers, threads and I/O of the
 * process. Without this, App Nap can de-prioritize the app once its window
 * loses focus or is not visible, which severely slows down blockchain
 * reindexing/resyncing since those run mostly on background threads.
 */
class MacNapInhibitor
{
public:
    /** Start suppressing App Nap. Safe to call multiple times. */
    static void disableAppNap();
    /** Stop suppressing App Nap. Safe to call even if never disabled. */
    static void enableAppNap();
};

#endif // BITCOIN_QT_MACNAPINHIBITOR_H
