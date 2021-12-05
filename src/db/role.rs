use serde::{
    Deserialize,
    Serialize,
};


#[derive(Clone, Serialize, sqlx::FromRow)]
pub struct Role {
    pub id: i32,
    pub account_id: i32,
    pub description: String,
    pub api_token: String,
}


#[derive(Clone, Debug, Deserialize, opg::OpgModel, PartialEq, Serialize, sqlx::FromRow)]
pub struct RolePermission {
    pub id: i32,
    pub role_id: i32,
    pub account_id: String,
    pub resource_type: String,
    pub resource_id: String,
    pub action_id: String,
}


// These are exposed for testing only; otherwise,
// the regular class is exposed
#[cfg(test)]
pub use mock::{
    MockRoleQuery as RoleQuery,
    MockRolePermissionQuery as RolePermissionQuery,
};


#[cfg(not(test))]
pub use live::{
    RolePermissionQuery,
    RoleQuery,
};


mod live {
    use crate::{
        database::PgPool,
        db::DatabaseError,
        schemas::RolePermissionPayload,
    };

    use super::{
        Role,
        RolePermission
    };


    pub struct RoleQuery {
        pool: PgPool,
    }


    pub struct RolePermissionQuery {
        pool: PgPool,
    }



    impl RoleQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                pool: pool
            }
        }

        pub async fn get(&self, id: i32) -> Result<Option<Role>, DatabaseError> {
            sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn create<S: AsRef<str> + Send>(&self, account_id: i32, description: S, api_token: S) -> Result<Role, DatabaseError> {
            sqlx::query_as::<_, Role>("INSERT INTO roles (account_id, description, api_token) VALUES ($1, $2, $3) RETURNING *")
                .bind(account_id)
                .bind(description.as_ref())
                .bind(api_token.as_ref())
                .fetch_one(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn update_token<S: AsRef<str> + Send>(&self, id: i32, api_token: S) -> Result<Option<Role>, DatabaseError> {
            sqlx::query_as::<_, Role>("UPDATE roles SET api_token = $1 WHERE id = $2 RETURNING *")
                .bind(api_token.as_ref())
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<Role>, DatabaseError> {
            sqlx::query_as::<_, Role>("DELETE FROM roles WHERE id = $1 RETURNING *")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn get_root_role(&self) -> Result<Option<Role>, DatabaseError> {
            let query = r#"
                SELECT * FROM roles
                INNER JOIN root_account_singleton
                ON roles.id = root_account_singleton.role_id;"#;

            sqlx::query_as::<_, Role>(query)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }
    }

    impl RolePermissionQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                pool: pool
            }
        }

        pub async fn get_by_role_id(&self, role_id: i32) -> Result<Vec<RolePermission>, DatabaseError> {
            sqlx::query_as::<_, RolePermission>("SELECT * FROM role_permissions WHERE role_id = $1")
                .bind(role_id)
                .fetch_all(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn get(&self, id: i32) -> Result<Option<RolePermission>, DatabaseError> {
            sqlx::query_as::<_, RolePermission>("SELECT * FROM role_permissions WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn create(&self, role_id: i32, permission: RolePermissionPayload) -> Result<RolePermission, DatabaseError> {
            let query = r#"INSERT INTO role_permissions
                (role_id, account_id, resource_type, resource_id, action_id) VALUES
                ($1, $2, $3, $4, $5) RETURNING *"#;

            sqlx::query_as::<_, RolePermission>(query)
                .bind(role_id)
                .bind(permission.account_id)
                .bind(permission.resource_type)
                .bind(permission.resource_id)
                .bind(permission.action_id)
                .fetch_one(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<RolePermission>, DatabaseError> {
            sqlx::query_as::<_, RolePermission>("DELETE FROM role_permissions WHERE id = $1 RETURNING *")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }
    }
}


#[cfg(test)]
pub mod mock {
    use std::{
        collections::HashMap,
        sync::{
            RwLock,
            atomic::{
                AtomicI32,
                Ordering,
            },
        },
    };

    use lazy_static::lazy_static;

    use crate::{
        database::PgPool,
        db::{
            DatabaseError,
            Role,
            RolePermission,
        },
        schemas::RolePermissionPayload,
    };


    const RESOURCES: &[&str] = &["accounts", "roles"];


    lazy_static! {
        static ref ROLE_MAP: RwLock<HashMap<i32, Role>> = {
            let mut map = HashMap::new();
            let nrole = Role {
                id: 1,
                account_id: 1,
                description: "Root account".to_owned(),
                api_token: "api_token".to_owned()
            };


            map.insert(1, nrole);
            RwLock::new(map)
        };

        static ref NEXT_ID: AtomicI32 = AtomicI32::new(2);
        static ref NEXT_PERM_ID: AtomicI32 = AtomicI32::new(2);

        static ref ROLE_PERM_MAP: RwLock<HashMap<i32, RolePermission>> = {
            let mut map = HashMap::new();

            for resource in RESOURCES {
                let nrole_perm = RolePermission {
                    id: 1,
                    role_id: 1,
                    account_id: "*".to_owned(),
                    resource_type: resource.to_string(),
                    resource_id: "*".to_owned(),
                    action_id: "*".to_string()
                };

                map.insert(1, nrole_perm);
            }

            RwLock::new(map)
        };
    }

    pub struct MockRoleQuery {
        _pool: PgPool,
    }


    pub struct MockRolePermissionQuery {
        _pool: PgPool,
    }


    impl MockRoleQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                _pool: pool
            }
        }

        pub async fn get(&self, id: i32) -> Result<Option<Role>, DatabaseError> {
            let maybe_role = ROLE_MAP.read()
                .expect("ROLE_MAP lock was poisoned!")
                .get(&id)
                .map(|e| e.to_owned());

            Ok(maybe_role)
        }

        pub async fn create<S: AsRef<str> + Send>(&self, account_id: i32, description: S, api_token: S) -> Result<Role, DatabaseError> {
            let mut map = ROLE_MAP.write()
                .expect("ROLE_MAP lock was poisoned!");
            let next_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

            let nentity = Role {
                id: next_id,
                account_id,
                description: description.as_ref()
                    .to_owned(),
                api_token: api_token.as_ref()
                    .to_owned(),
            };

            map.insert(next_id, nentity.clone());
            Ok(nentity)
        }

        pub async fn update_token<S: AsRef<str> + Send>(&self, id: i32, api_token: S) -> Result<Option<Role>, DatabaseError> {
            let mut map = ROLE_MAP.write()
                .expect("ROLE_MAP lock was poisoned!");

            let entry = map.get_mut(&id)
                .and_then(|e| {
                    e.api_token = api_token
                        .as_ref()
                        .to_owned();

                    Some(e.to_owned())
                });

            Ok(entry)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<Role>, DatabaseError> {
            let mut map = ROLE_MAP.write()
                .expect("ROLE_MAP lock was poisoned!");

            Ok(map.remove(&id))
        }

        pub async fn get_root_role(&self) -> Result<Option<Role>, DatabaseError> {
            let maybe_role = ROLE_MAP.read()
                .expect("ROLE_MAP lock was poisoned!")
                .get(&1)
                .map(|e| e.to_owned());

            Ok(maybe_role)
        }
    }


    impl MockRolePermissionQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                _pool: pool
            }
        }

        pub async fn get_by_role_id(&self, role_id: i32) -> Result<Vec<RolePermission>, DatabaseError> {
            let map = ROLE_PERM_MAP.read()
                .expect("ROLE_PERM_MAP lock was poisoned!");

            let nvec: Vec<RolePermission> = map
                .iter()
                .filter_map(|(_, e)| {
                    if e.role_id == role_id {
                        Some(e.to_owned())
                    } else {
                        None
                    }
                })
                .collect();

            Ok(nvec)
        }

        pub async fn get(&self, id: i32) -> Result<Option<RolePermission>, DatabaseError> {
            let ret = ROLE_PERM_MAP.read()
                .expect("ROLE_PERM_MAP lock was poisoned!")
                .get(&id)
                .and_then(|e| Some(e.to_owned()));

            Ok(ret)
        }

        pub async fn create(&self, role_id: i32, permission: RolePermissionPayload) -> Result<RolePermission, DatabaseError> {
            let mut map = ROLE_PERM_MAP.write()
                .expect("ROLE_PERM_MAP lock was poisoned!");
            let next_id = NEXT_PERM_ID.fetch_add(1, Ordering::Relaxed);
            let nrole_perm = RolePermission {
                id: next_id,
                role_id,
                account_id: permission.account_id,
                resource_type: permission.resource_type,
                resource_id: permission.resource_id,
                action_id: permission.action_id,
            };

            map.insert(next_id, nrole_perm.clone());
            Ok(nrole_perm)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<RolePermission>, DatabaseError> {
            let ret = ROLE_PERM_MAP.write()
                .expect("ROLE_PERM_MAP lock was poisoned!")
                .remove(&id);

            Ok(ret)
        }
    }
}


#[cfg(test)]
mod tests {
    use envconfig::Envconfig;

    use crate::{
        config::Configuration,
        db::{
            account::live::AccountQuery,
            tests::get_migrated_pool,
        },
        schemas::RolePermissionPayload,
    };

    use super::live::{
        RolePermissionQuery,
        RoleQuery,
    };


    fn config() -> Configuration {
        Configuration::init_from_env()
            .unwrap()
    }


    #[tokio::test]
    #[ignore]
    async fn test_roles() {
        let config = config();
        let pg = get_migrated_pool(&config)
            .await;
        let account = AccountQuery::new(pg.clone())
            .create("Dummy Role Test Account")
            .await
            .unwrap();
        let expected_overwrite = "overwritten_value";

        let query = RoleQuery::new(pg);
        let nrole = query.create(account.id, "dummy role", "abc123")
            .await
            .unwrap();

        let found = query.get(nrole.id)
            .await
            .unwrap()
            .expect("Failed to find created role");

        assert_eq!(nrole.id, found.id);

        let overwritten = query.update_token(nrole.id, expected_overwrite)
            .await
            .unwrap()
            .expect("Failed to update role");

        assert_eq!(overwritten.api_token, expected_overwrite);

        let deleted = query.delete(nrole.id)
            .await
            .unwrap()
            .expect("No returned deleted role");

        assert_eq!(deleted.id, nrole.id);

        let missing = query.get(nrole.id)
            .await
            .unwrap();

        assert!(missing.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_root_role() {
        let config = config();
        let pg = get_migrated_pool(&config)
            .await;
        let query = RoleQuery::new(pg)
            .get_root_role()
            .await
            .unwrap()
            .expect("Failed to get root role");

        assert_eq!(query.id, 1);
    }

    #[tokio::test]
    #[ignore]
    async fn test_role_permissions() {
        let config = config();
        let pg = get_migrated_pool(&config)
            .await;
        let account = AccountQuery::new(pg.clone())
            .create("Dummy Role Test Account")
            .await
            .unwrap();
        let query = RolePermissionQuery::new(pg.clone());
        let role = RoleQuery::new(pg.clone())
            .create(account.id, "dummy role", "abc123")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: "*".to_string(),
            resource_type: "roles".to_string(),
            resource_id: "*".to_string(),
            action_id: "read".to_string(),
        };

        let nperm = query.create(role.id, permission)
            .await
            .unwrap();

        let found = query.get(nperm.id)
            .await
            .unwrap()
            .expect("Failed to find created permission");

        assert_eq!(nperm.id, found.id);

        let deleted = query.delete(nperm.id)
            .await
            .unwrap()
            .expect("No returned deleted RolePermission");

        assert_eq!(deleted.id, nperm.id);

        let missing = query.get(nperm.id)
            .await
            .unwrap();

        assert!(missing.is_none());
    }

    #[tokio::test]
    #[ignore]
    async fn test_get_all_role_permissions() {
        let config = config();
        let pg = get_migrated_pool(&config)
            .await;
        let account = AccountQuery::new(pg.clone())
            .create("Dummy Role Test Account")
            .await
            .unwrap();
        let query = RolePermissionQuery::new(pg.clone());
        let role = RoleQuery::new(pg.clone())
            .create(account.id, "dummy role", "abc123")
            .await
            .unwrap();

        let permissions = vec![
            RolePermissionPayload {
                account_id: "*".to_string(),
                resource_type: "roles".to_string(),
                resource_id: "*".to_string(),
                action_id: "write".to_string(),
            },
            RolePermissionPayload {
                account_id: "*".to_string(),
                resource_type: "account".to_string(),
                resource_id: "*".to_string(),
                action_id: "read".to_string(),
            },
            RolePermissionPayload {
                account_id: "*".to_string(),
                resource_type: "account".to_string(),
                resource_id: "*".to_string(),
                action_id: "write".to_string(),
            },
        ];

        let len = permissions.len();

        for perm in permissions {
            query.create(
                role.id,
                perm,
            ).await
            .unwrap();
        }

        let all_perms = query.get_by_role_id(role.id)
            .await
            .unwrap();

        assert_eq!(len, all_perms.len());
    }
}

