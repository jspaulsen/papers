use opg::OpgModel;
use serde::{
    Deserialize,
    Serialize,
};

use crate::db::RolePermission;


#[derive(Deserialize, OpgModel)]
pub struct RolePayload {
    pub description: String
}


#[derive(Deserialize, OpgModel)]
pub struct RolePermissionPayload {
    pub account_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub action_id: String,
}


#[derive(Deserialize, OpgModel, Serialize)]
pub struct RolePermissionsResponsePayload {
    pub permissions: Vec<RolePermission>
}


#[derive(Deserialize, OpgModel, Serialize)]
pub struct RoleResponsePayload {
    pub id: i32,
    pub account_id: i32,
    pub description: String
}


impl From<crate::db::Role> for RoleResponsePayload {
    fn from(role: crate::db::Role) -> Self {
        Self {
            id: role.id,
            account_id: role.account_id,
            description: role.description,
        }
    }
}


impl From<Vec<crate::db::RolePermission>> for RolePermissionsResponsePayload {
    fn from(permissions: Vec<crate::db::RolePermission>) -> Self {
        Self {
            permissions
        }
    }
}
