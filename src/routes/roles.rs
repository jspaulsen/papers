use axum::{
    extract::{
        Extension,
        Path,
    },
    Json,
    response::IntoResponse,
};
use uuid::Uuid;

use crate::{
    database::PgPool,
    db::{
        Role,
        RoleQuery,
    },
    error::{
        HttpError,
        Loggable,
    },
    extractors::ClaimsExtractor,
    keys::SharedHmacKey,
    models::{
        ApiSecret,
        ResourceActions,
        ResourceType,
    },
    schemas::{
        RolePayload,
        RoleResponsePayload,
        TokenPayload,
    },
};


pub struct RoleRoute;


impl RoleRoute {
    pub async fn get(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id)): Path<(i32, i32)>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let s_role_id = role_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            Some(s_role_id.as_str()),
            &ResourceActions::Read,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let role: RoleResponsePayload = RoleQuery::new(db)
            .get(role_id)
            .await
            .log_error("Failed to retrieve role from database!")?
            .ok_or(HttpError::not_found(None))?
            .into();

        Ok(Json(role))
    }

    pub async fn get_secrets(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Extension(hmac): Extension<SharedHmacKey>,
        Path((account_id, role_id)): Path<(i32, i32)>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let s_role_id = role_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            Some(s_role_id.as_str()),
            &ResourceActions::Read,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let role: Role = RoleQuery::new(db)
            .get(role_id)
            .await
            .log_error("Failed to retrieve role from database!")?
            .ok_or(HttpError::not_found(None))?;

        let result: TokenPayload = ApiSecret::from_role(&role, &hmac)
            .into();

        Ok(Json(result))
    }

    pub async fn regenerate_secrets(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id)): Path<(i32, i32)>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let s_role_id = role_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            Some(s_role_id.as_str()),
            &ResourceActions::Modify,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let api_token = Uuid::new_v4()
            .to_string();


        RoleQuery::new(db)
            .update_token(role_id, api_token)
            .await
            .log_error("Failed to retrieve role from database!")?
            .ok_or(HttpError::not_found(None))?;

        let mut response = ().into_response();

        *response.status_mut() = http::StatusCode::NO_CONTENT;
        Ok(response)
    }

    pub async fn post(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path(account_id): Path<i32>,
        Json(payload): Json<RolePayload>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            None,
            &ResourceActions::Create,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let api_token = Uuid::new_v4()
            .to_string();

        let role: RoleResponsePayload = RoleQuery::new(db)
            .create(
                account_id,
                payload.description,
                api_token,
            )
            .await
            .log_error("Failed to create account in database!")?
            .into();

        let mut response = Json(role)
            .into_response();

        *response.status_mut() = http::StatusCode::CREATED;
        Ok(response)
    }

    pub async fn delete(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id)): Path<(i32, i32)>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let s_role_id = role_id.to_string();
        let has_perms = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            Some(s_role_id.as_str()),
            &ResourceActions::Delete,
        );

        if !has_perms {
            return Err(HttpError::unauthorized(None));
        }

        let role: RoleResponsePayload = RoleQuery::new(db)
            .delete(role_id)
            .await
            .log_error("Failed to retrieve account from database!")?
            .ok_or(HttpError::not_found(None))?
            .into();

        Ok(Json(role))
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
            AccountQuery,
            RoleQuery,
            RolePermissionQuery,
        },
        keys::{
            RsaPrivateKey,
            HmacKey,
            EncodingKeyPair,
        },
        models::{
            ApiSecret,
            Claims,
        },
        schemas::{
            RolePermissionPayload,
            RoleResponsePayload,
        },
        testing::default_config,
    };

    #[tokio::test]
    async fn test_get_role() {
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
            resource_type: "roles".to_string(),
            resource_id: "*".to_string(),
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

        let account_uri = format!("/v1/accounts/{}/roles/{}", account.id, role.id);
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

        let payload: RoleResponsePayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, role.id);
    }

    #[tokio::test]
    async fn test_get_role_fail() {
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

        let account_uri = format!("/v1/accounts/{}/roles/{}", account.id, role.id);
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
    async fn test_create_role() {
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
            resource_type: "roles".to_string(),
            resource_id: account.id.to_string(),
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
        let body = serde_json::json!({"description": "Dummy Role"});
        let uri = format!("/v1/accounts/{}/roles", account.id);

        let request = Request::builder()
            .uri(uri)
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

        let payload: RoleResponsePayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.account_id, account.id);
    }

    #[tokio::test]
    async fn test_create_role_fail() {
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

        let bearer = format!("Bearer {}", jwt);
        let body = serde_json::json!({"description": "Dummy account"});
        let uri = format!("/v1/accounts/{}/roles", account.id);

        let request = Request::builder()
            .uri(uri)
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
    async fn test_delete_role() {
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
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
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

        let uri = format!("/v1/accounts/{}/roles/{}", account.id, role.id);
        let bearer = format!("Bearer {}", jwt);

        let request = Request::builder()
            .uri(&uri)
            .method(http::Method::DELETE)
            .header("AUTHORIZATION", bearer)
            .body(Body::empty())
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let payload: RoleResponsePayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, role.id);
    }

    #[tokio::test]
    async fn test_get_role_secrets() {
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
            resource_type: "roles".to_string(),
            resource_id: "*".to_string(),
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

        let api_secrets = ApiSecret::from_role(&role, &hmac_key);

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/secrets", account.id, role.id);
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

        let payload: crate::schemas::TokenPayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.secret_access_key, api_secrets.api_secret);
    }

    #[tokio::test]
    async fn test_get_role_secrets_fail() {
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

        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let jwt = Claims::new(
            role.id,
            vec![],
        )
        .into_jwt(&jwt_keys.encode)
        .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/secrets", account.id, role.id);
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
    async fn test_regenerate_role_secrets() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let account = AccountQuery::new(db.clone())
            .create("Dummy Account")
            .await
            .unwrap();

        let overwritten_token = "overwritten-token";

        let role = RoleQuery::new(db.clone())
            .create(account.id, "Dummy Role", overwritten_token)
            .await
            .unwrap();
        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: "*".to_string(),
            action_id: "modify".to_string(),
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
            .layer(AddExtensionLayer::new(db.clone()))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/secrets/regenerate", account.id, role.id);
        let bearer = format!("Bearer {}", jwt);

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::POST)
            .header("AUTHORIZATION", bearer)
            .body(Body::empty())
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let nrole = RoleQuery::new(db)
            .get(role.id)
            .await
            .unwrap()
            .unwrap();

        assert_ne!(role.api_token, nrole.api_token);
    }

}
