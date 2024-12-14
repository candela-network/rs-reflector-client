# Reflector Oracle Smart Contract Client

This project provides rust bindings for [Reflector oracle smart contract](https://github.com/reflector-network/reflector-contract).

```rust 

use soroban_client::{
    network::{NetworkPassphrase, Networks},
    server::Options,
};

use reflector_client::{Asset, ReflectorClient, ReflectorContract};

...
...
    let xlm_asset = Asset::from_contract_id("CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA")?;
            
    let contract_id = "CALI2BYU2JE6WVRUFYTS6MSBNEHGJ35P4AVCZYF3B6QOE3QKOB2PLE6M";
    let rpc_url = "...";
    let client = ReflectorClient::new(
        contract_id,
        Networks::public().to_string(),
        rpc_url,
        Options {
            allow_http: None,
            timeout: Some(1000),
            headers: None,
        },
    )

    // Get the decimals used by the contract
    let decimals = client.decimals().await?;

    // Get the base asset of the contract
    let base_asset = client.base().await?;

    // Get the price of XLM in base asset
    let xlm_price = client
        .lastprice(xlm_asset)
        .await?
        .expect("No price for the asset");
...
...
```
