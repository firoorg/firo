// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2026 The Firo developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_DATABASE_H
#define FIRO_WALLET_DATABASE_H

#include "clientversion.h"
#include "streams.h"

#include <exception>
#include <memory>
#include <string>
#include <utility>

/** RAII interface for iterating serialized wallet database records. */
class DatabaseCursor
{
public:
    enum class Status {
        FAIL,
        MORE,
        DONE,
    };

    DatabaseCursor() = default;
    virtual ~DatabaseCursor() = default;

    DatabaseCursor(const DatabaseCursor&) = delete;
    DatabaseCursor& operator=(const DatabaseCursor&) = delete;

    virtual Status Next(CDataStream& key, CDataStream& value) = 0;
};

/** Backend-neutral access to one batch of serialized wallet records. */
class DatabaseBatch
{
private:
    virtual bool ReadRaw(CDataStream&& key, CDataStream& value) = 0;
    virtual bool WriteRaw(CDataStream&& key, CDataStream&& value, bool overwrite) = 0;
    virtual bool EraseRaw(CDataStream&& key) = 0;
    virtual bool HasRaw(CDataStream&& key) = 0;

public:
    DatabaseBatch() = default;
    virtual ~DatabaseBatch() = default;

    DatabaseBatch(const DatabaseBatch&) = delete;
    DatabaseBatch& operator=(const DatabaseBatch&) = delete;

    template <typename K, typename T>
    bool Read(const K& key, T& value)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        CDataStream value_stream(SER_DISK, CLIENT_VERSION);
        if (!ReadRaw(std::move(key_stream), value_stream)) {
            return false;
        }

        try {
            value_stream >> value;
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    template <typename K, typename T>
    bool Write(const K& key, const T& value, bool overwrite = true)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        CDataStream value_stream(SER_DISK, CLIENT_VERSION);
        value_stream.reserve(10000);
        value_stream << value;

        return WriteRaw(std::move(key_stream), std::move(value_stream), overwrite);
    }

    template <typename K>
    bool Erase(const K& key)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        return EraseRaw(std::move(key_stream));
    }

    template <typename K>
    bool Exists(const K& key)
    {
        CDataStream key_stream(SER_DISK, CLIENT_VERSION);
        key_stream.reserve(1000);
        key_stream << key;

        return HasRaw(std::move(key_stream));
    }

    virtual void Flush() = 0;
    virtual void Close() = 0;

    /** Iterate every record in serialized-key order. */
    virtual std::unique_ptr<DatabaseCursor> GetCursor() = 0;

    /** Iterate records beginning with the first serialized key not less than start_key. */
    virtual std::unique_ptr<DatabaseCursor> GetCursor(const CDataStream& start_key) = 0;

    virtual bool TxnBegin() = 0;
    virtual bool TxnCommit() = 0;
    virtual bool TxnAbort() = 0;
    virtual bool HasActiveTxn() const = 0;

    bool ReadVersion(int& version)
    {
        version = 0;
        return Read(std::string("version"), version);
    }

    bool WriteVersion(int version)
    {
        return Write(std::string("version"), version);
    }
};

#endif // FIRO_WALLET_DATABASE_H
