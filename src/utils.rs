use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRequest, RawPathParams, Request},
    http::StatusCode,
    response::IntoResponse,
    RequestExt,
};
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt;
use ruma::api::{
    client::{
        self,
        error::{ErrorBody, ErrorKind},
    },
    IncomingRequest, OutgoingResponse,
};

use crate::BridgeState;

#[derive(Debug)]
pub struct RumaRequest<T>(pub T);

#[async_trait]
impl<T> FromRequest<Arc<BridgeState>> for RumaRequest<T>
where
    T: IncomingRequest,
{
    type Rejection = axum::response::Response;

    async fn from_request(
        mut req: Request,
        state: &Arc<BridgeState>,
    ) -> Result<Self, Self::Rejection> {
        let hs_token = match req
            .extract_parts::<TypedHeader<Authorization<Bearer>>>()
            .await
        {
            Ok(v) => v.0 .0.token().to_owned(),
            Err(e) => {
                tracing::warn!("Malformed hs token: {e:?}");
                return Err(RumaResponse(client::Error::new(
                    StatusCode::FORBIDDEN,
                    ErrorBody::Standard {
                        kind: client::error::ErrorKind::forbidden(),
                        message: "malformed hs token".into(),
                    },
                ))
                .into_response());
            }
        };

        if hs_token != state.hs_token {
            return Err(RumaResponse(ruma::api::client::Error::new(
                StatusCode::FORBIDDEN,
                ErrorBody::Standard {
                    kind: ErrorKind::forbidden(),
                    message: "hs_token mismatch".into(),
                },
            ))
            .into_response());
        }

        // TODO: use the correct matrix error response
        let path_args = req
            .extract_parts::<RawPathParams>()
            .await
            .map_err(|e| e.into_response())?
            .into_iter()
            .map(|(_, value)| value.to_owned())
            .collect::<Vec<_>>();

        // TODO: use the correct matrix error response
        let (head, body) = req.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
            .to_bytes();

        match T::try_from_http_request(Request::from_parts(head, body), &path_args) {
            Ok(request) => Ok(RumaRequest(request)),
            Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string()).into_response()),
        }
    }
}

pub struct RumaResponse<T>(pub T);

impl<T> IntoResponse for RumaResponse<T>
where
    T: OutgoingResponse,
{
    fn into_response(self) -> axum::response::Response {
        match OutgoingResponse::try_into_http_response::<BytesMut>(self.0) {
            Ok(rsp) => rsp.map(|b| Bytes::from(b).into()),
            Err(e) => {
                tracing::error!("Error while creating response: {e:?}");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

impl<T: OutgoingResponse> From<T> for RumaResponse<T> {
    fn from(v: T) -> Self {
        Self(v)
    }
}
