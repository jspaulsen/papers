use std::{
    fs::File,
    path::Path,
};

use anyhow::Result;
use serde::Serialize;

use crate::{
    db::Role,
    keys::HmacKey,
};


#[derive(Serialize, opg::OpgModel)]
pub struct ApiSecret {
    pub role_id: i32,
    pub api_secret: String,
}


impl ApiSecret {
    pub fn from_role(role: &Role, signing_key: &HmacKey) -> Self {
        let api_secret = signing_key.sign(&role.api_token);

        Self {
            role_id: role.id,
            api_secret,
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let ret = serde_json::to_writer_pretty(
            File::create(path)?,
            self,
        )?;

        Ok(ret)
    }
}
