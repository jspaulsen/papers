pub use account::{
    Account,
    AccountQuery,
};
pub use role::{
    Role,
    RolePermission,
    RolePermissionQuery,
    RoleQuery,
};
pub use error::DatabaseError;


mod account;
mod error;
mod role;



#[cfg(test)]
pub mod tests {
    use crate::{
        config,
        database,
    };

    pub async fn get_migrated_pool(config: &config::Configuration) -> sqlx::PgPool {
        let pool = database::get_db_pool(&config)
            .await
            .unwrap();

        database::MIGRATE.run(&pool)
            .await
            .unwrap();

        pool
    }
}
