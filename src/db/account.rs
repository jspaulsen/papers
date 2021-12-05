use serde::{
    Deserialize,
    Serialize,
};


#[cfg(test)]
pub use mock::{
    MockAccountQuery as AccountQuery
};


#[cfg(not(test))]
pub use live::{
    AccountQuery,
};


#[derive(Clone, Deserialize,  opg::OpgModel, Serialize, sqlx::FromRow)]
pub struct Account {
    pub id: i32,
    pub description: String,
}



#[cfg(not(test))]
mod live {
    use crate::{
        database::PgPool,
        db::DatabaseError,
    };

    pub struct AccountQuery {
        pool: PgPool,
    }

    use super::Account;


    impl AccountQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                pool: pool
            }
        }

        pub async fn create<S: AsRef<str>>(&self, description: S) -> Result<Account, DatabaseError> {
            sqlx::query_as::<_, Account>("INSERT INTO accounts (description) VALUES ($1) RETURNING *")
                .bind(description.as_ref())
                .fetch_one(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn get(&self, id: i32) -> Result<Option<Account>, DatabaseError> {
            sqlx::query_as::<_, Account>("SELECT * FROM accounts WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(DatabaseError::from)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<Account>, DatabaseError> {
            sqlx::query_as::<_, Account>("DELETE FROM accounts WHERE id = $1 RETURNING *")
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
            Account,
            DatabaseError,
        },
    };


    lazy_static! {
        static ref ACCOUNT_MAP: RwLock<HashMap<i32, Account>> = {
            let mut map = HashMap::new();
            let naccount = Account {
                id: 1,
                description: "Root account".to_string(),
            };

            map.insert(1, naccount);
            RwLock::new(map)
        };

        static ref NEXT_ID: AtomicI32 = AtomicI32::new(2);
    }


    pub struct MockAccountQuery {
        _pool: PgPool,
    }

    impl MockAccountQuery {
        pub fn new(pool: PgPool) -> Self {
            Self {
                _pool: pool
            }
        }

        pub async fn create<S: AsRef<str>>(&self, description: S) -> Result<Account, DatabaseError> {
            let next_id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let naccount = Account {
                id: next_id,
                description: description.as_ref()
                    .to_owned()
            };

            ACCOUNT_MAP.write()
                .expect("ACCOUNT_MAP lock was poisoned!")
                .insert(next_id, naccount.clone());

            Ok(naccount)
        }

        pub async fn get(&self, id: i32) -> Result<Option<Account>, DatabaseError> {
            let result = ACCOUNT_MAP.read()
                .expect("ACCOUNT_MAP lock was poisoned!")
                .get(&id)
                .map(|e| e.to_owned());

            Ok(result)
        }

        pub async fn delete(&self, id: i32) -> Result<Option<Account>, DatabaseError> {
            let result = ACCOUNT_MAP.write()
                .expect("ACCOUNT_MAP lock was poisoned!")
                .remove(&id)
                .map(|e| e.to_owned());

            Ok(result)
        }
    }
}


#[cfg(test)]
mod tests {
    use envconfig::Envconfig;

    use crate::{
        config::Configuration,
        db::tests::get_migrated_pool,
    };

    use super::AccountQuery;

    fn config() -> Configuration {
        Configuration::init_from_env()
            .unwrap()
    }

    #[tokio::test]
    #[ignore]
    async fn test_accounts() {
        let config = config();
        let pg = get_migrated_pool(&config)
            .await;

        let query = AccountQuery::new(pg);
        let naccount = query.create("Dummy account")
            .await
            .unwrap();

        let found = query.get(naccount.id)
            .await
            .unwrap()
            .expect("Failed to find created account");

        assert_eq!(naccount.id, found.id);

        let deleted = query.delete(naccount.id)
            .await
            .unwrap()
            .expect("No returned deleted account");

        assert_eq!(deleted.id, naccount.id);

        let missing = query.get(naccount.id)
            .await
            .unwrap();

        assert!(missing.is_none());
    }
}
