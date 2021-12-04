use axum::{
    extract::Extension,
    response::IntoResponse,
    Json,
};


use crate::{
    database::PgPool,
    db::{
        RolePermissionQuery,
        RoleQuery,
    },
    error::{
        HttpError,
        AnyhowLoggable,
    },
    keys::{
        SharedHmacKey,
        SharedEncodingKeyPair,
    },
    models::Claims,
    schemas::{
        TokenPayload,
        JwtResponsePayload,
    },
};

pub struct TokenRoute;


impl TokenRoute {
    pub async fn post(
        Extension(db): Extension<PgPool>,
        Extension(jwt_keys): Extension<SharedEncodingKeyPair>,
        Extension(hmac_key): Extension<SharedHmacKey>,
        Json(body): Json<TokenPayload>,
    ) -> Result<impl IntoResponse, HttpError> {
        let role = RoleQuery::new(db.clone())
            .get(body.role_id)
            .await?
            .ok_or(HttpError::unauthorized(None))?;

        let permissions = RolePermissionQuery::new(db)
            .get_by_role_id(body.role_id)
            .await?;

        // Ensure provided secret matches token
        let verify = hmac_key.verify(
            &role.api_token,
            &body.secret_access_key,
        );

        if !verify {
            return Err(HttpError::unauthorized(None));
        }

        let claims = Claims::new(
            role.id,
            permissions,
        );

        let expiration = claims.exp as u64;
        let issued = claims.iat as u64;

        let result = JwtResponsePayload {
            expiration,
            issued,
            id_token: claims.into_jwt(&jwt_keys.encode)
                .log_error("Failed to encode JWT")?
        };

        Ok(Json(result))
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
    use serde_json::json;
    use tower::ServiceExt;

    use crate::{
        api::ApiBuilder,
        database::get_db_pool_lazy,
        db::RoleQuery,
        keys::{
            EncodingKeyPair,
            HmacKey,
            RsaPrivateKey,
        },
        schemas::JwtResponsePayload,
        testing::default_config,
    };


    #[tokio::test]
    async fn test_post_token() {
        let config = Arc::new(default_config());
        let rsa = RsaPrivateKey::new()
            .unwrap();
        let pg_pool = get_db_pool_lazy(&config)
            .await
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );

        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(pg_pool.clone()))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let role = RoleQuery::new(pg_pool)
            .get_root_role()
            .await
            .unwrap()
            .unwrap();

        let api_token = hmac_key.sign(&role.api_token)
            .to_string();
        let body = json!({"role_id": role.id, "secret_access_key": api_token});

        let request = Request::builder()
            .uri("/v1/token")
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let payload: JwtResponsePayload = serde_json::from_slice(
            &hyper::body::to_bytes(response.into_body())
                .await
                .unwrap()
        ).unwrap();

        let verify = crate::models::Claims::from_jwt(&payload.id_token, &jwt_keys.decode)
            .unwrap();

        assert_eq!(verify.sub, role.id);
    }


    #[tokio::test]
    async fn test_post_token_bad_request() {
        let config = Arc::new(default_config());
        let rsa = RsaPrivateKey::new()
            .unwrap();
        let pg_pool = get_db_pool_lazy(&config)
            .await
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );

        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(pg_pool.clone()))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let role = RoleQuery::new(pg_pool)
            .get_root_role()
            .await
            .unwrap()
            .unwrap();

        let api_token = hmac_key.sign(&role.api_token)
            .to_string();
        let body = json!({"no_role_id": role.id, "secret_access_key": api_token});

        let request = Request::builder()
            .uri("/v1/token")
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }


    #[tokio::test]
    async fn test_post_token_not_found() {
        let config = Arc::new(default_config());
        let rsa = RsaPrivateKey::new()
            .unwrap();
        let pg_pool = get_db_pool_lazy(&config)
            .await
            .unwrap();
        let jwt_keys = Arc::new(
            EncodingKeyPair::try_from(rsa)
                .unwrap()
        );

        let hmac_key = Arc::new(HmacKey::new(&*config.hmac_secret_key));

        let api = ApiBuilder::api_router()
            .layer(AddExtensionLayer::new(pg_pool.clone()))
            .layer(AddExtensionLayer::new(jwt_keys.clone()))
            .layer(AddExtensionLayer::new(hmac_key.clone()));

        let role = RoleQuery::new(pg_pool)
            .get_root_role()
            .await
            .unwrap()
            .unwrap();

        let api_token = hmac_key.sign(&role.api_token)
            .to_string();
        let body = json!({"role_id": 1235412515, "secret_access_key": api_token});

        let request = Request::builder()
            .uri("/v1/token")
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();

        let response = api
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
