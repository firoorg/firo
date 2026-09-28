// Copyright (c) 2026 The Firo Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "macnapinhibitor.h"

#undef slots
#include <Cocoa/Cocoa.h>

namespace {
// Holds the activity token returned by NSProcessInfo while App Nap is
// suppressed. nil when App Nap is not currently being inhibited.
id<NSObject> g_napActivityToken = nil;
} // namespace

void MacNapInhibitor::disableAppNap()
{
    if (g_napActivityToken != nil) return;

    // NSActivityUserInitiatedAllowingIdleSystemSleep tells the OS this
    // process is doing user-relevant work and should not be throttled by
    // App Nap, while still allowing the system to idle-sleep on its own
    // (unlike plain NSActivityUserInitiated, which also asserts
    // PreventUserIdleSystemSleep).
    g_napActivityToken = [[NSProcessInfo processInfo]
        beginActivityWithOptions:NSActivityUserInitiatedAllowingIdleSystemSleep
                           reason:@"Synchronizing with the Firo network"];
    [g_napActivityToken retain];
}

void MacNapInhibitor::enableAppNap()
{
    if (g_napActivityToken == nil) return;

    [[NSProcessInfo processInfo] endActivity:g_napActivityToken];
    [g_napActivityToken release];
    g_napActivityToken = nil;
}
