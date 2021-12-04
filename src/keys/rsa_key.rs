use std::{
    fs::read_to_string,
    path::Path,
};

use rand::rngs::OsRng;
use rsa::{
    pkcs8::{
        FromPrivateKey,
        ToPrivateKey,
    },
};


const RSA_NUM_BITS: usize = 2048;

pub struct RsaPrivateKey {
    key: rsa::RsaPrivateKey
}


impl RsaPrivateKey {
    pub fn new() -> anyhow::Result<Self> {
        let mut rng = OsRng;

        Ok(
            Self {
                key: rsa::RsaPrivateKey::new(
                    &mut rng,
                    RSA_NUM_BITS,
                )?
            }
        )
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let body = read_to_string(path)?;
        let ret = Self {
            key: rsa::RsaPrivateKey::from_pkcs8_pem(&body)?
        };

        Ok(ret)
    }

    pub fn public_key(&self) -> rsa::RsaPublicKey {
        rsa::RsaPublicKey::from(&self.key)
    }

    pub fn create(path: &Path) -> anyhow::Result<Self> {
        let nkey = Self::new()?;

        nkey.key
            .write_pkcs8_pem_file(path)?;

        Ok(nkey)
    }

    pub fn to_pkcs8_pem(self) -> Result<String, rsa::pkcs8::Error> {
        self.key
            .to_pkcs8_pem()
            .map(|s| {
                s.as_str()
                    .to_owned()
            })
    }
}
