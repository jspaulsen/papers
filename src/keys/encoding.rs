use jsonwebtoken::{
    DecodingKey,
    EncodingKey,
};
use rsa::{
    pkcs1::ToRsaPublicKey,
};


pub type SharedEncodingKeyPair = std::sync::Arc<EncodingKeyPair>;

pub struct EncodingKeyPair {
    pub decode: DecodingKey<'static>,
    pub encode: EncodingKey,
}


impl<'a> TryFrom<crate::keys::RsaPrivateKey> for EncodingKeyPair {
    type Error = anyhow::Error;

    fn try_from(key: crate::keys::RsaPrivateKey) -> Result<Self, Self::Error> {
        let pk_document = key
            .public_key()
            .to_pkcs1_pem()?;

        let privk_document = key.to_pkcs8_pem()?;

        let decode = DecodingKey::from_rsa_pem(pk_document.as_ref())?
            .into_static();

        let ret = Self {
            decode: decode,
            encode: EncodingKey::from_rsa_pem(privk_document.as_ref())?,
        };

        Ok(ret)
    }
}
