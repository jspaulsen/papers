use std::str::FromStr;

use log::LevelFilter;
use sqlx::{
    ConnectOptions,
    Error,
    migrate::Migrator,
    postgres::PgConnectOptions,
};
use super::config::Configuration;


pub use sqlx::PgPool;


pub static MIGRATE: Migrator = sqlx::migrate!();


pub async fn get_db_pool(config: &Configuration) -> Result<PgPool, Error> {
    let mut opts = PgConnectOptions::from_str(&config.database_uri)?;

    // TODO: is this what we want?
    opts.log_statements(LevelFilter::Debug);

    PgPool::connect_with(opts)
        .await
}


#[cfg(test)]
pub async fn get_db_pool_lazy(config: &Configuration) -> Result<PgPool, Error> {
    let opts = PgConnectOptions::from_str(&config.database_uri)?;
    Ok(PgPool::connect_lazy_with(opts))
}
