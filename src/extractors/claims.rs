use axum::{
    async_trait,
    extract::{
        FromRequest,
        RequestParts,
    },
};

use crate::{
    keys::SharedEncodingKeyPair,
    models::Claims,
    error::HttpError,
};


#[derive(Debug)]
pub struct ClaimsExtractor(pub Claims); //(pub Claims);


#[async_trait]
impl<B> FromRequest<B> for ClaimsExtractor
where
    B: Send,
{
    type Rejection = HttpError;

    async fn from_request(request: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let jwt_keys: &SharedEncodingKeyPair = request.extensions()
            .expect("Failed to retrieve Extensions from Request")
            .get()
            .expect("Failed to get SharedEncodingKeyPair from Extensions");

        let claims = Claims::from_jwt(
            jwt_from_request(request)?,
            &jwt_keys.decode,
        ).map_err(|_| HttpError::unauthorized(None))?;

        Ok(Self(claims))
    }
}


fn jwt_from_request<B>(request: &RequestParts<B>) -> Result<String, HttpError> {
    let header = request
        .headers()
        .ok_or(HttpError::internal_server_error(None))?
        .get(http::header::AUTHORIZATION)
        .ok_or(HttpError::unauthorized(None))?
        .to_str()
        .map_err(|_| HttpError::unauthorized(None))?;


    let (schema, token) = header
        .split_once(' ')
        .ok_or(HttpError::unauthorized(None))?;

    if schema != "Bearer" {
        Err(HttpError::unauthorized(None))
    }else {
        Ok(token.to_owned())
    }
}
