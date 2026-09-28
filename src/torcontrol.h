// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with Tor.
 */
#ifndef BITCOIN_TORCONTROL_H
#define BITCOIN_TORCONTROL_H

#include "scheduler.h"

extern const std::string DEFAULT_TOR_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

/**
 * Start the Tor control thread.
 *
 * @param onion_local_port  Local 127.0.0.1 port that Tor should forward
 *                          inbound hidden-service traffic to. Must be a port
 *                          on a listener bound with is_onion_listener=true so
 *                          that accepted connections are classified as
 *                          NET_ONION. Pass 0 if no dedicated listener could be
 *                          bound; in that case the Tor controller will fall
 *                          back to forwarding to the shared listen port and
 *                          inbound peers will be classified as IPv4 (the
 *                          pre-fix behavior).
 */
void StartTorControl(boost::thread_group& threadGroup, CScheduler& scheduler,
                     unsigned short onion_local_port = 0);
void InterruptTorControl();
void StopTorControl();

#endif /* BITCOIN_TORCONTROL_H */
