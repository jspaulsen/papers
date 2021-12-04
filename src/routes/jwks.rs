use axum::{
    body::Full,
    extract::{
        Extension,
    },
    response::IntoResponse,
};


use crate::keys::SharedJwks;


pub struct JwksRoute;


impl JwksRoute {
    pub async fn get(
        Extension(jwks): Extension<SharedJwks>,
    ) -> http::Response<Full<axum::body::Bytes>> {
        jwks.into_response()
    }
}
