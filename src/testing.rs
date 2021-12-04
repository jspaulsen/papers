use std::collections::HashMap;

use envconfig::Envconfig;

use crate::{
    config::Configuration,
};


pub fn default_config() -> Configuration {
    let mut hashmap = HashMap::new();

    hashmap.insert("DATABASE_URI".to_string(), "postgres://localhost/mydb".to_string());
    hashmap.insert("CARGO_PKG_VERSION".to_string(), "1.0.0".to_string());
    hashmap.insert(
        "HMAC_SECRET_KEY".to_string(),
        "d84f6e8740cc7803518b1e890c4324afe1ee154500beb61ab7bce1f430972e3b".to_string(),
    );

    Configuration::init_from_hashmap(&hashmap)
        .unwrap()
}
