use std::{
    ops::Deref,
    path::{
        PathBuf,
    },
    net::IpAddr,
    str::FromStr,
    sync::Arc,
};


use envconfig::Envconfig;
use hex;
use tracing_subscriber::EnvFilter;


pub type SharedConfiguration = Arc<Configuration>;


const JWS_PEM_FNAME: &str = "jws.pem";
const ROOT_SECRETS_FNAME: &str = "secrets.json";


pub const APPLICATION_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_JWKS_CACHE_DURATION: u64 = 3600;
pub const DEFAULT_TOKEN_EXPIRATION: usize = 3600; // 60m duration
pub const DEFAULT_TOKEN_LEEWAY: u64 = 10;
pub const JWT_ISSUER: &str = "papers";
pub const JWT_KID: &str = "papers_kid";



#[derive(Debug, Envconfig)]
pub struct Configuration {
    #[envconfig(from = "DATABASE_URI")]
    pub database_uri: String,

    #[envconfig(from = "HMAC_SECRET_KEY")]
    pub hmac_secret_key: HexStr,

    #[envconfig(from = "APP_DATA_DIR", default = "/var/lib/papers")]
    pub app_data_dir: PathBuf,

    #[envconfig(from = "HTTP_PORT", default = "8080")]
    pub http_port: u16,

    #[envconfig(from = "HTTP_BIND_ADDRESS", default = "0.0.0.0")]
    pub http_bind_address: IpAddr,

    #[envconfig(from = "LOG_LEVEL", default = "INFO")]
    pub log_level: EnvFilter,

    #[envconfig(from = "REISSUE_ROOT_SECRETS", default = "false")]
    pub reissue_root_secrets: bool,
}


impl Configuration {
    pub fn jws_path(&self) -> PathBuf {
        self.app_data_dir
            .join(JWS_PEM_FNAME)
    }

    pub fn root_secrets_path(&self) -> PathBuf {
        self.app_data_dir
            .join(ROOT_SECRETS_FNAME)
    }
}


#[derive(Debug)]
pub struct HexStr {
    internal: Vec<u8>
}


impl FromStr for HexStr {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(
            Self {
                internal: hex::decode(s)?
            }
        )
    }
}


impl Deref for HexStr {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.internal
    }
}
