use axum::{
    body::Full,
    response::IntoResponse,
};
use base64;
use rsa::{
    PublicKeyParts,
    RsaPublicKey,
};
use serde::{
    Deserialize,
    Serialize,
};

use crate::config::{
    DEFAULT_JWKS_CACHE_DURATION,
    JWT_KID,
};


pub type SharedJwks = std::sync::Arc<Jwks>;


#[derive(Serialize, Deserialize)]
pub struct Jwk {
    kty: String,
    r#use: String,
    alg: String,
    kid: String,
    n: String,
    e: String,
}


#[derive(Serialize, Deserialize)]
pub struct Jwks {
    keys: Vec<Jwk>,
}


impl From<Jwk> for Jwks {
    fn from(key: Jwk) -> Self {
        Self {
            keys: vec![key],
        }
    }
}


impl Jwk {
    pub fn from_public_key(public_key: &RsaPublicKey) -> Self {
        let kid = JWT_KID.to_owned();

        let n = public_key
            .n()
            .to_bytes_be();

        let e = public_key
            .e()
            .to_bytes_be();

        Self {
            kty: "RSA".to_string(),
            r#use: "sig".to_string(),
            alg: "RSA256".to_string(),
            kid,
            n: base64::encode_config(n, base64::URL_SAFE_NO_PAD),
            e: base64::encode_config(e, base64::URL_SAFE_NO_PAD),
        }
    }
}


impl IntoResponse for &Jwks {
    type Body = Full<axum::body::Bytes>;
    type BodyError = <Self::Body as axum::body::HttpBody>::Error;

    fn into_response(self) -> http::Response<Self::Body> {
        let cache_v = format!("private, max-age={}", DEFAULT_JWKS_CACHE_DURATION);
        let body = serde_json::to_vec(&self)
            .expect("Failed to serialize JWKS; this should never fail");

        http::Response::builder()
            .header(http::header::CACHE_CONTROL, cache_v)
            .header(http::header::CONTENT_TYPE, "application/json")
            .status(http::StatusCode::OK)
            .body(Full::from(body))
            .expect("Failed to create Response for JWKS; this should never fail")
    }
}


#[cfg(test)]
mod tests {
    use base64;
    use rand::rngs::OsRng;
    use rsa::{
        BigUint,
        PaddingScheme,
        PublicKey,
        RsaPublicKey,
        RsaPrivateKey,
    };

    use crate::keys::Jwk;

    #[test]
    fn test_jwk() {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 256)
            .expect("Failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);
        let jwks = Jwk::from_public_key(&public_key);

        let message = "encrypt_me_please".as_bytes();

        let n = BigUint::from_bytes_be(
            &base64::decode_config(jwks.n, base64::URL_SAFE_NO_PAD)
                .unwrap()
        );

        let e = BigUint::from_bytes_be(
            &base64::decode_config(jwks.e, base64::URL_SAFE_NO_PAD)
                .unwrap()
        );

        let npublic_key = RsaPublicKey::new(n, e)
            .expect("Failed to create new Public Key from Jwk");

        // Encrypt with newly generated public key
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let enc_data = npublic_key.encrypt(&mut rng, padding, &message[..]).expect("failed to encrypt");

        // Decrypt
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let dec_data = private_key.decrypt(padding, &enc_data).expect("failed to decrypt");

        assert_eq!(&message[..], &dec_data[..]);
    }
}
