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
        RolePermission,
        RolePermissionQuery,
    },
    models::{
        ResourceActions,
        ResourceType
    },
    error::{
        HttpError,
        Loggable,
    },
    extractors::ClaimsExtractor,
    schemas::{
        RolePermissionPayload,
        RolePermissionsResponsePayload,
    },
};


pub struct RolePermissionRoute;


impl RolePermissionRoute {
    pub async fn get(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id, permission_id)): Path<(i32, i32, i32)>,
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

        let permission: RolePermission = RolePermissionQuery::new(db)
            .get(permission_id)
            .await
            .log_error("Failed to retrieve RolePermission from database!")?
            .ok_or(HttpError::not_found(None))?;

        Ok(Json(permission))
    }

    pub async fn get_all(
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

        let permissions: RolePermissionsResponsePayload = RolePermissionQuery::new(db)
            .get_by_role_id(role_id)
            .await
            .log_error("Failed to retrieve RolePermissions from database!")?
            .into();

        Ok(Json(permissions))
    }

    pub async fn post(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id)): Path<(i32, i32)>,
        Json(payload): Json<RolePermissionPayload>,
    ) -> Result<impl IntoResponse, HttpError> {
        let s_account_id = account_id.to_string();
        let s_role_id = role_id.to_string();
        let can_modify = claims.has_permission_for(
            Some(s_account_id.as_str()),
            &ResourceType::Roles,
            Some(s_role_id.as_str()),
            &ResourceActions::Modify,
        );

        let has_access_to = claims.has_permission_for(
            Some(payload.account_id.as_str()),
            ResourceType::Roles.as_ref(),
            None,
            ResourceActions::Modify.as_ref()
        );

        if !can_modify {
            return Err(HttpError::unauthorized(None));
        }

        if !has_access_to {
            return Err(HttpError::unauthorized(None));
        }

        let permission: RolePermission = RolePermissionQuery::new(db)
            .create(role_id, payload)
            .await
            .log_error("Failed to create RolePermission in database")?;

        let mut response = Json(permission)
            .into_response();

        *response.status_mut() = http::StatusCode::CREATED;
        Ok(response)
    }

    pub async fn delete(
        Extension(db): Extension<PgPool>,
        ClaimsExtractor(claims): ClaimsExtractor,
        Path((account_id, role_id, permission_id)): Path<(i32, i32, i32)>,
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

        let permission: RolePermission = RolePermissionQuery::new(db)
            .delete(permission_id)
            .await
            .log_error("Failed to delete RolePermission from database")?
            .ok_or(HttpError::not_found(None))?
            .into();

        Ok(Json(permission))
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
        database::{self, PgPool},
        config::Configuration,
        db::{
            Account,
            AccountQuery,
            RoleQuery,
            RolePermissionQuery,
            RolePermission,
        },
        keys::{
            RsaPrivateKey,
            HmacKey,
            EncodingKeyPair,
        },
        models::Claims,
        schemas::{
            RolePermissionPayload,
            RolePermissionsResponsePayload,
        },
        testing::default_config,
    };


    fn generate_keys(config: &Configuration) -> (Arc<EncodingKeyPair>, Arc<HmacKey>) {
        let rsa = RsaPrivateKey::new()
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );
        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        (jwt_keys, hmac_key)
    }


    async fn new_account(db: PgPool) -> Account {
        let account = AccountQuery::new(db)
            .create("Dummy Account")
            .await
            .unwrap();

        account
    }


    #[tokio::test]
    async fn test_get_role_permission() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
            action_id: "read".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();
        let permission_id = permission.id;

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions/{}", account.id, role.id, permission_id);
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

        let payload: RolePermission = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, permission_id);
    }

    #[tokio::test]
    async fn test_get_role_permission_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: "wrong-role-id".to_string(),
            action_id: "read".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();
        let permission_id = permission.id;

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions/{}", account.id, role.id, permission_id);
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
    async fn test_get_all_role_permissions() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
            action_id: "read".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();
        let permission_id = permission.id;

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions", account.id, role.id);
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

        let payload: RolePermissionsResponsePayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.permissions.len(), 1);
        assert_eq!(payload.permissions[0].id, permission_id);
    }

    #[tokio::test]
    async fn test_get_all_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: "wrong-role-id".to_string(),
            action_id: "read".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions", account.id, role.id);
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
    async fn test_create_role_permission() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
            action_id: "modify".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions", account.id, role.id);
        let bearer = format!("Bearer {}", jwt);
        let body = serde_json::json!({
            "account_id": account.id.to_string(),
            "resource_type": "accounts",
            "resource_id": account.id.to_string(),
            "action_id": "write",
        });

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::POST)
            .header("Content-Type", "application/json")
            .header("AUTHORIZATION", bearer)
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        let payload: RolePermission = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.account_id, account.id.to_string());
    }

    #[tokio::test]
    async fn test_create_role_permission_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
            action_id: "modify".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions", account.id, role.id);
        let bearer = format!("Bearer {}", jwt);
        let body = serde_json::json!({
            "account_id": "*".to_string(), // shouldn't have permission for this
            "resource_type": "accounts",
            "resource_id": account.id.to_string(),
            "action_id": "write",
        });

        let request = Request::builder()
            .uri(&account_uri)
            .method(http::Method::POST)
            .header("Content-Type", "application/json")
            .header("AUTHORIZATION", bearer)
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_role_permission() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
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
        let permission_id = permission.id;

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions/{}", account.id, role.id, permission_id);
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

        let payload: RolePermission = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        assert_eq!(payload.id, permission_id);
    }

    #[tokio::test]
    async fn test_delete_role_permission_fail() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
            .await
            .unwrap();

        let permission = RolePermissionPayload {
            account_id: account.id.to_string(),
            resource_type: "roles".to_string(),
            resource_id: role.id.to_string(),
            action_id: "modify".to_string(),
        };

        let permission = RolePermissionQuery::new(db.clone())
            .create(role.id, permission)
            .await
            .unwrap();
        let permission_id = permission.id;

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions/{}", account.id, role.id, permission_id);
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

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_delete_role_permission_not_found() {
        let config = Arc::new(default_config());
        let db = database::get_db_pool_lazy(&config)
            .await
            .unwrap();
        let (jwt_keys, _hmac_key) = generate_keys(&config);
        let account = new_account(db.clone()).await;

        let role = RoleQuery::new(db.clone())
            .create(account.id, "dummy-role", "api-token")
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

        let jwt = Claims::new(role.id, vec![permission])
            .into_jwt(&jwt_keys.encode)
            .unwrap();

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(db))
            .layer(AddExtensionLayer::new(jwt_keys.clone()));

        let account_uri = format!("/v1/accounts/{}/roles/{}/permissions/{}", account.id, role.id, 2147483647);
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

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
