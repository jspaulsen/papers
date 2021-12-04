use axum::{
    extract::Extension,
    body::Full,
    response::IntoResponse,
};
use serde_yaml;

use crate::{
    error::{
        HttpError,
        AnyhowLoggable,
    },
};


pub struct OpenApiRoute;


impl OpenApiRoute {
    pub async fn yaml(
        Extension(docs): Extension<opg::Opg>
    ) -> Result<impl IntoResponse, HttpError> {
        let body = serde_yaml::to_vec(&docs)
            .log_error("Failed to serialize OpenApi docs!")?;

        let response = http::Response::builder()
            .header(http::header::CONTENT_TYPE, "application/yaml")
            .status(http::StatusCode::OK)
            .body(Full::from(body))
            .log_error("Failed to build OpenApi yaml response!")?;

        Ok(response)
    }

    pub async fn html() -> impl IntoResponse {
        let body = r#"
            <!DOCTYPE html>
            <html>
            <head>
                <title>Redoc</title>
                <!-- needed for adaptive design -->
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">

                <!--
                Redoc doesn't change outer page styles
                -->
                <style>
                body {
                    margin: 0;
                    padding: 0;
                }
                </style>
            </head>
            <body>
                <redoc spec-url='api.yaml'></redoc>
                <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"> </script>
            </body>
            </html>
        "#;

        axum::response::Html(body)
    }
}
