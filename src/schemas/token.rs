use opg::OpgModel;
use serde::{
    Deserialize,
    Serialize,
};

use crate::models::ApiSecret;


#[derive(Deserialize, OpgModel, Serialize)]
pub struct TokenPayload {
    pub role_id: i32,
    pub secret_access_key: String,
}


impl From<ApiSecret> for TokenPayload {
    fn from(secret: ApiSecret) -> Self {
        Self {
            role_id: secret.role_id,
            secret_access_key: secret.api_secret
        }
    }
}
