use axum::{
    extract::{
        Extension,
        Path,
    },
    Json,
    response::IntoResponse,
};

use crate::{
    database::PgPool,
    db::{
        AccountQuery,
    },
    error::{
        HttpError,
        Loggable,
    },
    extractors::ClaimsExtractor,
    models::{
        ResourceActions,
        ResourceType,
    },
    schemas::AccountPayload,
};


pub struct AccountRoute;


impl AccountRoute {
    pub async fn get(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path(account_id): Path<i32>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let has_perms = claims.has_permission_for(
            None,
            ResourceType::Accounts.as_ref(),
            Some(s_account_id.as_str()),
            &ResourceActions::Read,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let account = AccountQuery::new(db)
            .get(account_id)
            .await
            .log_error("Failed to retrieve account from database!")?
            .ok_or(HttpError::not_found(None))?;

        Ok(Json(account))
    }

    pub async fn post(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Json(payload): Json<AccountPayload>,
    ) -> Result<impl IntoResponse, HttpError> {
        let has_perms = claims.has_permission_for(
            Some("*"),
            &ResourceType::Accounts,

            // Awkward but accounts are created against root account
            // which isn't well represented in this scheme
            Some("*"),
            &ResourceActions::Create,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let account = AccountQuery::new(db)
            .create(&payload.description)
            .await
            .log_error("Failed to create account in database!")?;

        let mut response = Json(account)
            .into_response();

        *response.status_mut() = http::StatusCode::CREATED;
        Ok(response)
    }

    pub async fn delete(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path(account_id): Path<i32>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Accounts,
            None,
            &ResourceActions::Delete,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let account = AccountQuery::new(db)
            .delete(account_id)
            .await
            .log_error("Failed to retrieve account from database!")?
            .ok_or(HttpError::not_found(None))?;

        Ok(Json(account))
    }
}


#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        AddExtensionLayer,
        body::Body,
        http::{
            Request,
            StatusCode,
        },
    };
    use tower::ServiceExt;

    use crate::{
        api::ApiBuilder,
        database,
        db::{
            Account,
            AccountQuery,
            RoleQuery,
            RolePermissionQuery,
        },
        keys::{
            RsaPrivateKey,
            HmacKey,
            EncodingKeyPair,
        },
        models::Claims,
        schemas::{
            RolePermissionPayload,
        },
        testing::default_config,
    };

    #[tokio::test]
    async fn test_get_account() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let account = AccountQuery::new(db.clone())
            .create("Dummy Account")
            .await
            .unwrap();
        let role = RoleQuery::new(db.clone())
            .create(account.id, "Dummy Role", "this-is-a-token")
            .await
            .unwrap();
        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "accounts".to_string(),
            resource_id: account.id.to_string(),
            action_id: "read".to_string(),
        };
        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![permission],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}", account.id);
        let bearer = format!("Bearer {}", jwt);

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::GET)
            .header("AUTHORIZATION", bearer)
            .body(Body::empty())
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let payload: Account = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, account.id);
    }

    #[tokio::test]
    async fn test_get_account_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let account = AccountQuery::new(db.clone())
            .create("Dummy Account")
            .await
            .unwrap();
        let role = RoleQuery::new(db.clone())
            .create(account.id, "Dummy Role", "this-is-a-token")
            .await
            .unwrap();
        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "accounts".to_string(),
            resource_id: account.id.to_string(),
            action_id: "write".to_string(),
        };
        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![permission],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}", account.id);
        let bearer = format!("Bearer {}", jwt);

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::GET)
            .header("AUTHORIZATION", bearer)
            .body(Body::empty())
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_create_account() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();

        let role = RoleQuery::new(db.clone())
            .create(1, "Dummy Role", "this-is-a-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: "*".to_string(),
            resource_type: "accounts".to_string(),
            resource_id: "*".to_string(),
            action_id: "create".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![permission],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let bearer = format!("Bearer {}", jwt);
        let body = serde_json::json!({"description": "Dummy account"});

        let request = Request::builder()
            .uri("/v1/accounts")
            .method(http::Method::POST)
            .header("AUTHORIZATION", bearer)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let payload: Account = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.description, "Dummy account");
    }

    #[tokio::test]
    async fn test_create_account_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let role = RoleQuery::new(db.clone())
            .create(1, "Dummy Role", "this-is-a-token")
            .await
            .unwrap();
        let permission = RolePermissionPayload {
            account_id: 1.to_string(),
            resource_type: "accounts".to_string(),
            resource_id: 1.to_string(),
            action_id: "read".to_string(),
        };
        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![permission],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let bearer = format!("Bearer {}", jwt);
        let body = serde_json::json!({"description": "Dummy account"});

        let request = Request::builder()
            .uri("/v1/accounts")
            .method(http::Method::POST)
            .header("AUTHORIZATION", bearer)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_account() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let account = AccountQuery::new(db.clone())
            .create("Dummy Account")
            .await
            .unwrap();
        let role = RoleQuery::new(db.clone())
            .create(account.id, "Dummy Role", "this-is-a-token")
            .await
            .unwrap();
        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "accounts".to_string(),
            resource_id: account.id.to_string(),
            action_id: "delete".to_string(),
        };
        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![permission],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}", account.id);
        let bearer = format!("Bearer {}", jwt);

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::DELETE)
            .header("AUTHORIZATION", bearer)
            .body(Body::empty())
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let payload: Account = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, account.id);
    }
}
