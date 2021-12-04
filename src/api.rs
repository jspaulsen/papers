use axum::{
    Router,
    routing::{
        get,
        post,
    },
};

use tower::ServiceBuilder;
use tower_http::{
    add_extension::AddExtensionLayer,
    trace::TraceLayer,
};

use crate::{
    config::SharedConfiguration,
    database::PgPool,
    keys::{
        SharedEncodingKeyPair,
        SharedHmacKey,
        SharedJwks,
    },
    routes::{
        AccountRoute,
        JwksRoute,
        HealthcheckRoute,
        OpenApiRoute,
        RolePermissionRoute,
        RoleRoute,
        TokenRoute,
    },
};


pub struct ApiBuilder {
    config: Option<SharedConfiguration>,
    jwks: Option<SharedJwks>,
    jwt_keys: Option<SharedEncodingKeyPair>,
    docs: Option<opg::Opg>,
    pool: Option<PgPool>,
    hmac: Option<SharedHmacKey>,
}


impl ApiBuilder {
    pub fn new() -> Self {
        Self {
            config: None,
            jwks: None,
            jwt_keys: None,
            docs: None,
            pool: None,
            hmac: None,
        }
    }

    pub fn config(mut self, config: SharedConfiguration) -> Self {
        self.config = Some(config);
        self
    }

    pub fn jwks(mut self, jwks: SharedJwks) -> Self {
        self.jwks = Some(jwks);
        self
    }

    pub fn jwt_keys(mut self, jwt_keys: SharedEncodingKeyPair) -> Self {
        self.jwt_keys = Some(jwt_keys);
        self
    }

    pub fn docs(mut self, docs: opg::Opg) -> Self {
        self.docs = Some(docs);
        self
    }

    pub fn pool(mut self, pool: PgPool) -> Self {
        self.pool = Some(pool);
        self
    }

    pub fn hmac(mut self, hmac: SharedHmacKey) -> Self {
        self.hmac = Some(hmac);
        self
    }

    pub fn api_router() -> Router {
        let jwks = get(JwksRoute::get);
        let healthcheck = get(HealthcheckRoute::get);
        let routes_account_id = get(AccountRoute::get)
            .delete(AccountRoute::delete);
        let routes_role_id = get(RoleRoute::get)
            .delete(RoleRoute::delete);
        let routes_role_permissions = get(RolePermissionRoute::get_all)
            .post(RolePermissionRoute::post);
        let routes_role_permission_id = get(RolePermissionRoute::get)
            .delete(RolePermissionRoute::delete);

        // Nest account routes
        let account_nested = Router::new()
            .route("/", post(AccountRoute::post))
            .route("/:account_id", routes_account_id)
            .route("/:account_id/roles", post(RoleRoute::post))
            .route("/:account_id/roles/:role_id", routes_role_id)
            .route("/:account_id/roles/:role_id/secrets", get(RoleRoute::get_secrets))
            .route("/:account_id/roles/:role_id/secrets/regenerate", post(RoleRoute::regenerate_secrets))
            .route("/:account_id/roles/:role_id/permissions", routes_role_permissions)
            .route("/:account_id/roles/:role_id/permissions/:permission_id", routes_role_permission_id);

        let nested = Router::new()
            .route("/docs/api.yaml", get(OpenApiRoute::yaml))
            .route("/docs/api.html", get(OpenApiRoute::html))
            .route("/token", post(TokenRoute::post))
            .nest("/accounts", account_nested);

        Router::new()
            .route("/.well-known/jwks.json", jwks)
            .route("/healthcheck", healthcheck)
            .nest("/v1", nested)
            .layer(TraceLayer::new_for_http())
    }

    pub fn build(self) -> Router {
        let layers = ServiceBuilder::new()
            .layer(AddExtensionLayer::new(self.config.expect("Builder requires SharedConfiguration")))
            .layer(AddExtensionLayer::new(self.jwks.expect("Builder requires SharedJwks")))
            .layer(AddExtensionLayer::new(self.jwt_keys.expect("Builder requires SharedEncodingKeyPair")))
            .layer(AddExtensionLayer::new(self.docs.expect("Builder requires Open Api docs")))
            .layer(AddExtensionLayer::new(self.pool.expect("Builder requires DB pool")))
            .layer(AddExtensionLayer::new(self.hmac.expect("Builder requires HMAC secret key")))
            .into_inner();

        Self::api_router()
            .layer(layers)
    }
}
