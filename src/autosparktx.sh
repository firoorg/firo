#!/bin/bash

function check_jq {
    if ! command -v jq &> /dev/null; then
        echo "jq not found. Installing jq..."
        sudo apt update
        sudo apt install -y jq
    fi
}

# Call the check_jq function to ensure jq is available
check_jq

function createSpendSparkTx {
    local amount=$1
    local address=$2

    tx=$(./firo-cli -testnet spendspark "{\"$address\":{\"amount\":$amount, \"subtractFee\": false}}")
    sleep 30
    echo "$tx"
}

function mintSpark {
    local amount=$1
    local spAddress=$2

    minttx_list=$(./firo-cli -testnet mintspark "{\""$spAddress"\":{\"amount\":$amount, \"memo\":\"test_memo\"}}")
    sleep 30
    echo "$minttx_list" | jq -r '.[]'
}

function check_confirmation_status {
    local tx_id=$1
    while (true); do
        confirmationStatus=$(./firo-cli -testnet gettransaction "$tx_id" | jq '.confirmations')
        if [ "$confirmationStatus" -eq 0 ]; then
            echo "Transaction $tx_id is in the mempool. Please wait ..."
            sleep 30
        else
            echo "Transaction $tx_id confirmed."
            break
        fi
    done
}

while true; do

    sparkBalance=$(./firo-cli -testnet getsparkbalance)
    availableBalance=$(echo "$sparkBalance" | jq '.availableBalance')

    spAddress=$(./firo-cli -testnet getnewsparkaddress | jq -r '.[0]')
    if ((availableBalance < 1)); then
        echo "Insufficient mints on the balance. Calling mintspark ..."
        for i in {1..5}; do
            firoBalance=$(./firo-cli -testnet getbalance)
            if ((firoBalance < 1)); then
                echo "You don't have enough funds to generate mints !"
                exit 1
            fi
            sptx_list=$(mintSpark "0.5" "$spAddress")
            for sptx in $sptx_list; do
                check_confirmation_status "$sptx"
            done
         done
         echo "5 mints successfully created."
    fi

    echo "Start spendspark ..."

    for i in {1..5}; do
        spendtx=$(createSpendSparkTx "0.5" "$spAddress")
        check_confirmation_status "$spendtx"
    done

    read -p "Do you want to continue (yes/no)? " user_input
    case "$user_input" in
        "yes")
            continue
        ;;
        "no")
            break
        ;;
        *)
            echo "Invalid command: $user_input"
        ;;
    esac

done