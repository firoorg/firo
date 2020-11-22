Elysium
===============

Lelantus
--------------

Lelantus protocol is allowed on token layer(Elysium). Each token owner can decide to enable or disable. There are four status that can be set.

`Soft Enable` would allow user to use Lelantus protocol on that token but token owner could change the status anytime.
`Hard Enable` would allow user to use Lelantus protocol on that token permanently.
`Soft Disable` would not allow user to use Lelantus protocol on that token but token owner could change the status anytime.
`Hard Disable` would not allow user to use Lelantus protocol on that token permanently.

To Use Lelantus protocol on current version, token creator have to set status correctly and enabled block need to be reached.

Command to create a token that can have Lelantus protocol on it is shown below.

`zcoin-cli -regtest elysium_sendissuancefixed <owner address> 1 1 0 '' '' 'Lelantus' '' '' '1000000' 0 1`

Last flag represent Lelantus status that creator need to set(0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled).

NOTE: `owner address` have to have some transparent XZC to pay fee.

After the transaction to create an asset is mined, you could check token id by.

`zcoin-cli -regtest elysium_listproperties`

Because we create the asset by `elysium_sendissuancefixed` so token creator would have `1000000 token` now.

After block number exceed Lelantus on Elysium enabled block(1000 for regtest) we could create a mint using command below.

`zcoin-cli -regtest elysium_sendlelantusmint <from address> <lelantus_property> "10"`

After the transaction is processed, `10 tokens` should be minted. You could check list of mints by.

`zcoin-cli -regtest elysium_listlelantusmints`

The coin should be shown. But now we have only one coin in group so we have to create more to make it spendable.

Before spend coins we have to have Lelantus coins on base layer to pay fee(Transparent balance could not be used in this case). You can create some Lelantus coin on base layer and spend some coin on token layer by commands following.

`zcoin-cli -regtest mintlelantus 1`

NOTE: don't forget to create Lelantus coins on base layer more than 1 to make it spendable. And don't forget to create some blocks(10 blocks is safe).

`zcoin-cli -regtest elysium_sendlelantusspend <send_to_address> <lelantus_property> '1'`

If the transaction is included on chain correctly, balance of `<send_to_address>` should be added and spended coin would not be shown in `zcoin-cli -regtest elysium_listlelantusmints`. But if there are change from spend transaction new Lelantus mint would be created.

To ensure fund be added to destination address, you could check balance by

`zcoin-cli -regtest elysium_getbalance <address> <lelantus_property>`

TODO: status updating.