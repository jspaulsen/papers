use axum::{
    extract::Extension,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_debug::debug_handler;
use sqlx::{
    Pool,
    Postgres,
};


pub struct HealthcheckRoute;


// TODO: finish me
impl HealthcheckRoute {
    #[debug_handler]
    pub async fn get(
        Extension(_db): Extension<Pool<Postgres>>,
    ) -> Result<impl IntoResponse, StatusCode> {
        let body = serde_json::json!({"status": "acceptable"});
        Ok(
            Json(body)
        )
    }
}
