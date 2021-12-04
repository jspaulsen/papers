use opg::OpgModel;
use serde::{
    Deserialize,
    Serialize,
};


#[derive(Deserialize, OpgModel, Serialize)]
pub struct JwtResponsePayload {
    pub id_token: String,
    pub expiration: u64,
    pub issued: u64,
}
