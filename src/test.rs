use soroban_client::{
    address::AddressTrait as _,
    network::{NetworkPassphrase, Networks},
    server::Options,
};

use crate::{Asset, ReflectorClient, ReflectorContract};

fn get_client() -> ReflectorClient {
    let contract_id = "CALI2BYU2JE6WVRUFYTS6MSBNEHGJ35P4AVCZYF3B6QOE3QKOB2PLE6M";
    let rpc_url = "https://mainnet.sorobanrpc.com"; // Thank you!
    ReflectorClient::new(
        contract_id,
        Networks::public().to_string(),
        rpc_url,
        Options {
            allow_http: None,
            timeout: Some(1000),
            headers: None,
        },
    )
}

#[tokio::test]
async fn test_lasttimestamp() {
    let client = get_client();
    let ts = client
        .last_timestamp()
        .await
        .expect("lastimestamp could not be retrieved");

    println!("last timestamp: {}", ts);
}
#[tokio::test]
async fn test_admin() {
    let client = get_client();
    let admin = client.admin().await.expect("admin could not be retrieved");

    println!("admin: {}", admin.to_string());
}

#[tokio::test]
async fn test_lastprice() {
    let xlm_asset =
        Asset::from_contract_id("CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA")
            .expect("Cannot create Asset");
    println!("Asset: {:?}", xlm_asset.to_contract_id());
    let client = get_client();
    let decimals = client.decimals().await.expect("Could not get decimals");

    let base_asset = client.base().await.expect("Cannot retrieve base asset");
    let xlm_price = client
        .lastprice(xlm_asset)
        .await
        .expect("Could not be retrieved last XLM price")
        .expect("No price for the asset");

    println!(
        "Last for XLM: {} in asset {}",
        xlm_price.price(decimals),
        base_asset.to_contract_id().unwrap()
    );
}
