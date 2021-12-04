use opg::OpgModel;
use serde::Deserialize;


#[derive(Deserialize, OpgModel)]
pub struct AccountPayload {
    pub description: String
}
