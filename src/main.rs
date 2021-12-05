use std::{
    net::SocketAddr,
    sync::Arc,
};

use anyhow::Context;
use envconfig::Envconfig;

use api::ApiBuilder;
use keys::{
    EncodingKeyPair,
    HmacKey,
    Jwk,
    Jwks,
    RsaPrivateKey,
};

use util::get_root_secrets;


mod api;
mod config;
mod database;
mod db;
mod error;
mod extractors;
mod keys;
mod models;
mod openapi;
mod routes;
mod schemas;
mod util;


#[cfg(test)]
mod testing;


#[tokio::main]
async fn main() {
    let config = Arc::new(
        config::Configuration::init_from_env()
            .unwrap()
    );

    let jws_fpath = config.jws_path();

    // Initialize logging at configured level
    tracing_subscriber::fmt()
        .with_env_filter(
            config
                .log_level
                .to_string()
        )
        .init();

    // Determine if our private key exists; if not, generate it
    let rsa_key = if jws_fpath.exists() {
        tracing::info!("Loading RSA PEM from {:?}", jws_fpath);

        RsaPrivateKey::load(&jws_fpath)
            .expect("Failed to load RSA private key")
    } else {
        tracing::info!("Creating new RSA private key at {:?}", jws_fpath);

        RsaPrivateKey::create(&jws_fpath)
            .context("Check that application data directory exists and application has permissions")
            .expect("Failed to create new RSA private key")
    };

    // Generate JWK from RSA signing key
    let jwks = Arc::new(
        Jwks::from(
            Jwk::from_public_key(
                &rsa_key.public_key()
            )
        )
    );

    // Generate jwt keys from RsaPrivateKey
    let jwt_keys = Arc::new(
        EncodingKeyPair::try_from(rsa_key)
            .expect("Failed to generate JWT encoding key pair from RSA key")
    );

    // Generate HMAC key from configuration
    let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

    // Generate OpenApi docs
    let docs = openapi::generate_opg_api(config::APPLICATION_VERSION);

    let database = database::get_db_pool(&config)
        .await
        .expect("Failed to setup database connection pool!");

    //attempt to setup migrations as part of application startup
    database::MIGRATE.run(&database)
        .await
        .expect("Failed to run database migrations!");

    // If the `REISSUE_ROOT_SECRETS flag is true, generate a secrets file from the root user
    if config.reissue_root_secrets {
        let secrets_fpath = config.root_secrets_path();

        tracing::warn!("REISSUE_ROOT_SECRETS is true; generating secrets file in {:?}", secrets_fpath);

        let secrets = get_root_secrets(database.clone(), &hmac_key) // TODO: wrong type
            .await
            .expect("Failed to generate root secrets");

        secrets.save(&secrets_fpath)
            .expect("Failed to save secrets to data directory!");
    }

    let socket = SocketAddr::from((config.http_bind_address, config.http_port));
    let api: axum::Router = ApiBuilder::new()
        .config(config)
        .jwks(jwks)
        .jwt_keys(jwt_keys)
        .docs(docs)
        .pool(database)
        .hmac(hmac_key)
        .build();

    tracing::info!("Listening for connections on {}", socket);

    axum::Server::bind(&socket)
        .serve(api.into_make_service())
        .await
        .unwrap()
}
