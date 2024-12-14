use std::cell::RefCell;
use std::rc::Rc;

use soroban_client::account::{Account, AccountBehavior};
use soroban_client::address::{Address, AddressTrait};
use soroban_client::contract::{ContractBehavior, Contracts};
use soroban_client::server::{Options, Server};
use soroban_client::soroban_rpc::soroban_rpc::RawSimulateTransactionResponse;
use soroban_client::transaction::TransactionBuilder;
use soroban_client::transaction_builder::{TransactionBuilderBehavior, TIMEOUT_INFINITE};
use soroban_client::xdr::xdr::next::int128_helpers::*;
use soroban_client::xdr::xdr::next::{
    Hash, Limits, ReadXdr, ScAddress, ScMap, ScSymbol, ScVal, ScVec,
};
use thiserror::Error;

pub trait ReflectorContract {
    type Error;

    /// get base asset the price is reported in
    fn base(&self) -> impl std::future::Future<Output = Result<Asset, Self::Error>>;

    ///get number of decimal places used to represent price for all assets quoted by the oracle
    fn decimals(&self) -> impl std::future::Future<Output = Result<u32, Self::Error>>;

    ///get all assets quoted by the contract
    fn assets(&self) -> impl std::future::Future<Output = Result<Vec<Asset>, Self::Error>>;

    ///get the most recent price update timestamp
    fn last_timestamp(&self) -> impl std::future::Future<Output = Result<u64, Self::Error>>;

    ///get asset price in base asset at specific timestamp
    fn price(
        &self,
        asset: Asset,
        timestamp: u64,
    ) -> impl std::future::Future<Output = Result<Option<PriceData>, Self::Error>>;

    ///get the most recent price for an asset
    fn lastprice(
        &self,
        asset: Asset,
    ) -> impl std::future::Future<Output = Result<Option<PriceData>, Self::Error>>;

    ///get last N price records for the given asset
    fn prices(
        &self,
        asset: Asset,
        records: u32,
    ) -> impl std::future::Future<Output = Result<Option<Vec<PriceData>>, Self::Error>>;

    ///get the most recent cross price record for the pair of assets
    fn x_last_price(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
    ) -> impl std::future::Future<Output = Result<Option<PriceData>, Self::Error>>;

    ///get the cross price for the pair of assets at specific timestamp
    fn x_price(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        timestamp: u64,
    ) -> impl std::future::Future<Output = Result<Option<PriceData>, Self::Error>>;

    ///get last N cross price records of for the pair of assets
    fn x_prices(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        records: u32,
    ) -> impl std::future::Future<Output = Result<Option<Vec<PriceData>>, Self::Error>>;

    ///get the time-weighted average price for the given asset over N recent records
    fn twap(
        &self,
        asset: Asset,
        records: u32,
    ) -> impl std::future::Future<Output = Result<Option<i128>, Self::Error>>;

    ///get the time-weighted average cross price for the given asset pair over N recent records
    fn x_twap(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        records: u32,
    ) -> impl std::future::Future<Output = Result<Option<i128>, Self::Error>>;

    ///get price feed resolution (default tick period timeframe, in seconds)
    fn resolution(&self) -> impl std::future::Future<Output = Result<u32, Self::Error>>;

    ///get historical records retention period, in seconds
    fn period(&self) -> impl std::future::Future<Output = Result<Option<u64>, Self::Error>>;

    ///get contract protocol version
    fn version(&self) -> impl std::future::Future<Output = Result<u32, Self::Error>>;

    //get contract admin address
    fn admin(&self) -> impl std::future::Future<Output = Result<Address, Self::Error>>;
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PriceData {
    pub price: i128,
    pub timestamp: u64,
}

impl PriceData {
    pub fn price(&self, decimals: u32) -> f64 {
        (self.price as f64) / 10f64.powi(decimals as i32)
    }
}

impl TryFrom<ScVal> for PriceData {
    type Error = ReflectorError;

    fn try_from(value: ScVal) -> Result<Self, Self::Error> {
        let mut price: i128 = 0;
        let mut timestamp: u64 = 0;
        if let ScVal::Map(Some(ScMap(vm))) = value {
            for m in vm.iter() {
                //
                if let ScVal::Symbol(ScSymbol(s)) = &m.key {
                    match s.to_string().as_str() {
                        "price" => {
                            price = match &m.val {
                                ScVal::I128(i) => i128_from_pieces(i.hi, i.lo),
                                _ => -1,
                            }
                        }
                        "timestamp" => {
                            timestamp = match &m.val {
                                ScVal::U64(i) => *i,
                                _ => return Err(ReflectorError::InvalidConversion),
                            }
                        }
                        _ => return Err(ReflectorError::InvalidConversion),
                    }
                }
            }
            return Ok(PriceData { price, timestamp });
        }
        Err(ReflectorError::InvalidConversion)
    }
}
#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub enum Asset {
    Stellar([u8; 32]), // Address does not implement Debug, Ord, ...
    Other(String),
}

impl Asset {
    pub fn from_contract_id(id: &str) -> Option<Self> {
        if let Ok(stellar_strkey::Strkey::Contract(stellar_strkey::Contract(key))) =
            stellar_strkey::Strkey::from_string(id)
        {
            Some(Asset::Stellar(key))
        } else {
            None
        }
    }
    pub fn to_contract_id(&self) -> Option<String> {
        match self {
            Asset::Stellar(addr) => {
                Some(stellar_strkey::Strkey::Contract(stellar_strkey::Contract(*addr)).to_string())
            }
            Asset::Other(_) => None,
        }
    }
}

impl TryFrom<ScVal> for Asset {
    type Error = ReflectorError;

    fn try_from(value: ScVal) -> Result<Self, Self::Error> {
        if let ScVal::Vec(Some(ScVec(vm))) = value {
            if let ScVal::Symbol(ScSymbol(s)) = vm[0].clone() {
                match s.to_string().as_str() {
                    "Stellar" => {
                        if let ScVal::Address(ScAddress::Contract(addr)) = vm[1].clone() {
                            return Ok(Asset::Stellar(addr.0));
                        }
                    }
                    "Other" => {
                        if let ScVal::Symbol(sym) = vm[1].clone() {
                            return Ok(Asset::Other(sym.to_string()));
                        }
                    }
                    _ => {}
                }
            }
        }
        Err(ReflectorError::InvalidConversion)
    }
}

impl TryFrom<Asset> for ScVal {
    type Error = ReflectorError;

    fn try_from(value: Asset) -> Result<ScVal, ReflectorError> {
        match value {
            Asset::Stellar(sc_address) => {
                let stellar = ScSymbol::try_from(Vec::from("Stellar".as_bytes()))?;

                let t = ScVal::Symbol(stellar);
                let addr = ScVal::Address(ScAddress::Contract(Hash::from(sc_address)));
                Ok(ScVal::Vec(Some(ScVec([t, addr].try_into()?))))
            }
            Asset::Other(s) => {
                let stellar = "Other".as_bytes();
                let t = ScVal::Symbol(ScSymbol(stellar.try_into()?));
                let sym = ScVal::Symbol(ScSymbol::try_from(Vec::from(s.as_bytes()))?);
                Ok(ScVal::Vec(Some(ScVec([t, sym].try_into()?))))
            }
        }
    }
}

#[derive(Error, Debug)]
#[repr(u32)]
pub enum ReflectorError {
    #[error("Already initialized")]
    AlreadyInitialized = 0,
    #[error("Unauthorized")]
    Unauthorized = 1,
    #[error("AssetMissing")]
    AssetMissing = 2,
    #[error("AssetAlreadyExists")]
    AssetAlreadyExists = 3,
    #[error("InvalidConfigVersion")]
    InvalidConfigVersion = 4,
    #[error("InvalidTimestamp")]
    InvalidTimestamp = 5,
    #[error("InvalidUpdateLength")]
    InvalidUpdateLength = 6,
    #[error("AssetLimitExceeded")]
    AssetLimitExceeded = 7,
    #[error("InvalidConversion")]
    InvalidConversion,
    #[error("DefaultError")]
    DefaulError,
    #[error("SorobanError")]
    SorobanError(#[from] soroban_client::xdr::xdr::next::Error),
    #[error("UnknownError")]
    UnknownError(#[from] Box<dyn std::error::Error>),
}

pub struct ReflectorClient {
    contract: Contracts,
    network: String,
    server: Server,
}

impl ReflectorClient {
    pub fn new(contract_id: &str, network: String, rpc_url: &str, opts: Options) -> Self {
        ReflectorClient {
            contract: Contracts::new(contract_id).unwrap(),
            network,
            server: Server::new(rpc_url, opts),
        }
    }

    async fn invoke(
        &self,
        method: &str,
        params: Option<Vec<ScVal>>,
    ) -> Result<RawSimulateTransactionResponse, ReflectorError> {
        let source_account = Rc::new(RefCell::new(
            Account::new(
                "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                "0",
            )
            .unwrap(),
        ));

        let contract_tx = TransactionBuilder::new(source_account, self.network.as_str(), None)
            .fee(0u32)
            .add_operation(self.contract.call(method, params))
            .set_timeout(TIMEOUT_INFINITE)
            .expect("Timeout setting failed, it should not")
            .build();

        self.server
            .simulate_transaction(contract_tx, None)
            .await
            .map_err(ReflectorError::UnknownError)
    }
}

impl ReflectorContract for ReflectorClient {
    type Error = ReflectorError;
    async fn base(&self) -> Result<Asset, ReflectorError> {
        let response = self.invoke("base", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let val: Asset =
                ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none())?.try_into()?;
            return Ok(val);
        }
        Err(ReflectorError::DefaulError)
    }

    async fn decimals(&self) -> Result<u32, Self::Error> {
        let response = self.invoke("decimals", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            if let ScVal::U32(val) = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none())? {
                return Ok(val);
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn resolution(&self) -> Result<u32, Self::Error> {
        let response = self.invoke("resolution", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::U32(val)) => return Ok(val),
                _ => return Err(ReflectorError::DefaulError),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn period(&self) -> Result<Option<u64>, Self::Error> {
        let response = self.invoke("period", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::U64(v)) => return Ok(Some(v)),
                _ => return Ok(None),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn assets(&self) -> Result<Vec<Asset>, Self::Error> {
        let response = self.invoke("assets", None).await?;
        to_vec_asset(response)
    }

    async fn last_timestamp(&self) -> Result<u64, Self::Error> {
        let response = self.invoke("last_timestamp", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::U64(v)) => return Ok(v),
                _ => return Err(ReflectorError::DefaulError),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn price(&self, asset: Asset, timestamp: u64) -> Result<Option<PriceData>, Self::Error> {
        let val_asset: ScVal = asset.try_into()?;
        let val_timestamp: ScVal = timestamp.into();
        let response = self
            .invoke("price", Some([val_asset, val_timestamp].into()))
            .await?;
        to_price_data(response)
    }

    async fn lastprice(&self, asset: Asset) -> Result<Option<PriceData>, Self::Error> {
        let val: ScVal = asset.try_into()?;
        let response = self.invoke("lastprice", Some([val].into())).await?;
        to_price_data(response)
    }

    async fn prices(
        &self,
        asset: Asset,
        records: u32,
    ) -> Result<Option<Vec<PriceData>>, Self::Error> {
        let val_asset: ScVal = asset.try_into()?;
        let response = self
            .invoke("prices", Some([val_asset, records.into()].into()))
            .await?;
        to_vec_price_data(response)
    }

    async fn x_last_price(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
    ) -> Result<Option<PriceData>, Self::Error> {
        let val_base: ScVal = base_asset.try_into()?;
        let val_quote: ScVal = quote_asset.try_into()?;
        let response = self
            .invoke("x_last_price", Some([val_base, val_quote].into()))
            .await?;
        to_price_data(response)
    }
    async fn x_price(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        timestamp: u64,
    ) -> Result<Option<PriceData>, Self::Error> {
        let val_base: ScVal = base_asset.try_into()?;
        let val_quote: ScVal = quote_asset.try_into()?;
        let response = self
            .invoke(
                "x_price",
                Some([val_base, val_quote, timestamp.into()].into()),
            )
            .await?;
        to_price_data(response)
    }

    async fn x_prices(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        records: u32,
    ) -> Result<Option<Vec<PriceData>>, Self::Error> {
        let val_base: ScVal = base_asset.try_into()?;
        let val_quote: ScVal = quote_asset.try_into()?;
        let response = self
            .invoke(
                "x_prices",
                Some([val_base, val_quote, records.into()].into()),
            )
            .await?;
        to_vec_price_data(response)
    }

    async fn twap(&self, asset: Asset, records: u32) -> Result<Option<i128>, Self::Error> {
        let val_asset: ScVal = asset.try_into()?;
        let response = self
            .invoke("twap", Some([val_asset, records.into()].into()))
            .await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::I128(v)) => return Ok(Some(i128_from_pieces(v.hi, v.lo))),
                _ => return Ok(None),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn x_twap(
        &self,
        base_asset: Asset,
        quote_asset: Asset,
        records: u32,
    ) -> Result<Option<i128>, Self::Error> {
        let val_base: ScVal = base_asset.try_into()?;
        let val_quote: ScVal = quote_asset.try_into()?;
        let response = self
            .invoke("x_twap", Some([val_base, val_quote, records.into()].into()))
            .await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::I128(v)) => return Ok(Some(i128_from_pieces(v.hi, v.lo))),
                _ => return Ok(None),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn version(&self) -> Result<u32, Self::Error> {
        let response = self.invoke("version", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(ScVal::U32(v)) => return Ok(v),
                _ => return Err(ReflectorError::DefaulError),
            }
        }
        Err(ReflectorError::DefaulError)
    }

    async fn admin(&self) -> Result<Address, Self::Error> {
        let response = self.invoke("admin", None).await?;
        if let Some(vres) = response.results {
            let res = vres.first().unwrap().to_owned();
            let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
            match decoded {
                Ok(scval) => return Ok(Address::from_sc_val(&scval).unwrap()),
                _ => return Err(ReflectorError::DefaulError),
            }
        }
        Err(ReflectorError::DefaulError)
    }
}

fn to_vec_asset(response: RawSimulateTransactionResponse) -> Result<Vec<Asset>, ReflectorError> {
    if let Some(vres) = response.results {
        let res = vres.first().unwrap().to_owned();
        let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
        match decoded {
            Ok(ScVal::Vec(Some(ScVec(v)))) => {
                let vvv: Vec<Asset> = v.iter().map(|x| x.clone().try_into().unwrap()).collect();
                return Ok(vvv);
            }
            _ => return Err(ReflectorError::DefaulError),
        }
    }
    Err(ReflectorError::DefaulError)
}

fn to_price_data(
    response: RawSimulateTransactionResponse,
) -> Result<Option<PriceData>, ReflectorError> {
    if let Some(vres) = response.results {
        let res = vres.first().unwrap().to_owned();
        let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
        match decoded {
            Ok(pricedata) => return Ok(Some(pricedata.try_into()?)),
            _ => return Ok(None),
        }
    }

    Err(ReflectorError::DefaulError)
}

fn to_vec_price_data(
    response: RawSimulateTransactionResponse,
) -> Result<Option<Vec<PriceData>>, ReflectorError> {
    if let Some(vres) = response.results {
        let res = vres.first().unwrap().to_owned();
        let decoded = ScVal::from_xdr_base64(res.xdr.unwrap(), Limits::none());
        match decoded {
            Ok(ScVal::Vec(Some(ScVec(v)))) => {
                let vvv: Vec<PriceData> = v.iter().map(|x| x.clone().try_into().unwrap()).collect();
                return Ok(Some(vvv));
            }
            _ => return Ok(None),
        }
    }

    Err(ReflectorError::DefaulError)
}

#[cfg(test)]
mod test;
