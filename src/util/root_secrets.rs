use crate::{
    database::PgPool,
    db::RoleQuery,
    models::ApiSecret,
    keys::HmacKey,
};


pub async fn get_root_secrets(pool: PgPool, key: &HmacKey) -> anyhow::Result<ApiSecret> {
    let maybe_role = RoleQuery::new(pool)
        .get_root_role()
        .await?;

    let role = if let Some(role) = maybe_role {
        role
    } else {
        anyhow::bail!("Missing root role from database; have migrations run?")
    };

    Ok(ApiSecret::from_role(&role, key))
}
