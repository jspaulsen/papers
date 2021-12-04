use sha2::Sha256;
use hex;
use hmac::{
    Hmac,
    Mac,
    NewMac,
};


// Create alias for HMAC-SHA256
pub type HmacSha256 = Hmac<Sha256>;
pub type SharedHmacKey = std::sync::Arc<HmacKey>;


pub struct HmacKey {
    key: HmacSha256,
}


impl HmacKey {
    pub fn new<S: AsRef<[u8]>>(key: S) -> Self {
        Self {
            key: HmacSha256::new_from_slice(key.as_ref())
                .expect("HmacSha256 allows for variable key length; this should never fail")
        }
    }

    pub fn sign<S: AsRef<str>>(&self, message: S) -> String {
        let mut mac = self.key
            .clone();

        let message = message.as_ref()
            .as_bytes();

        mac.update(message);

        hex::encode(
            mac.finalize()
                .into_bytes()
                .to_vec()
        )
    }

    pub fn verify<S: AsRef<str>>(&self, message: S, signed: S) -> bool {
        let mut mac = self.key
            .clone();

        let message = message.as_ref()
            .as_bytes();

        let signed = {
            let decoded = hex::decode(signed.as_ref());

            if let Ok(decoded) = decoded {
                decoded
            } else {
                return false;
            }
        };

        mac.update(&message);

        match mac.verify(signed.as_ref()) {
            Ok(()) => true,
            Err(_) => false
        }
    }
}


#[cfg(test)]
mod tests {
    use hex;

    use super::HmacKey;

    const HMAC_KEY: &str = "d84f6e8740cc7803518b1e890c4324afe1ee154500beb61ab7bce1f430972e3b";

    #[test]
    fn test_hmac_key() {
        let wrong_key = hex::decode(
            "a82c5c47c59f781a60f0c0efe27e62c6b32e22f93fd47b4a2137c34d900ea197"
        ).unwrap();

        let raw_key = hex::decode(HMAC_KEY)
            .unwrap();

        let message = "This is an encoded message";

        let hmac_key = HmacKey::new(raw_key);
        let wrong_hmac_key = HmacKey::new(wrong_key);

        let signature = hmac_key.sign(message);
        let wrong_signature = wrong_hmac_key.sign(message);

        assert!(hmac_key.verify(message, &signature));
        assert!(!hmac_key.verify(message, &wrong_signature));
    }
}
