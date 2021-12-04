use chrono;
use jsonwebtoken;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    config::{
        DEFAULT_TOKEN_LEEWAY,
        DEFAULT_TOKEN_EXPIRATION,
        JWT_ISSUER,
        JWT_KID,
    },
    db::RolePermission,
};


#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Claims {
    //aud: String,         // Optional. Audience
    pub exp: usize,          // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    pub iat: usize,          // Optional. Issued at (as UTC timestamp)
    pub iss: String,         // Optional. Issuer
    //nbf: usize,          // Optional. Not Before (as UTC timestamp)
    pub sub: i32,         // Optional. Subject (whom token refers to)
    pub permissions: Vec<RolePermission>,
}


impl Claims {
    pub fn new<P: AsRef<[RolePermission]>>(subject: i32, permissions: P) -> Self {
        let now = chrono::Utc::now()
            .timestamp() as usize;

        Self {
            exp: now + DEFAULT_TOKEN_EXPIRATION,
            iat: now,
            iss: JWT_ISSUER.to_owned(),
            sub: subject,
            permissions: permissions.as_ref()
                .to_owned()
        }
    }

    pub fn into_jwt(self, key: &jsonwebtoken::EncodingKey) -> Result<String, jsonwebtoken::errors::Error> {
        let kid = JWT_KID.to_owned();

        let header = jsonwebtoken::Header {
            typ: None,
            alg: jsonwebtoken::Algorithm::RS256,
            cty: None,
            jku: None,
            kid: Some(kid),
            x5u: None,
            x5t: None,
        };

        jsonwebtoken::encode(
            &header,
            &self,
            key,
        )
    }

    /// Decodes and validates a JWT, returning the inner claims
    pub fn from_jwt<S: AsRef<str>>(jwt: S, key: &jsonwebtoken::DecodingKey) -> Result<Claims, jsonwebtoken::errors::Error> {
        let validation = jsonwebtoken::Validation {
            leeway: DEFAULT_TOKEN_LEEWAY,
            validate_exp: true,
            validate_nbf: false,
            aud: None,
            iss: Some(JWT_ISSUER.to_owned()),
            sub: None,
            algorithms: vec![jsonwebtoken::Algorithm::RS256],
        };

        let token = jsonwebtoken::decode::<Claims>(
            jwt.as_ref(),
            &key,
            &validation,
        )?;

        Ok(token.claims)
    }

    pub fn has_permission_for<S: AsRef<str>>(&self, account_id: Option<S>, resource_type: S, resource_id: Option<S>, action: S) -> bool {
        let account_id = account_id.as_ref();
        let resource_type = resource_type.as_ref();
        let action = action.as_ref();
        let permissions: Vec<&RolePermission> = self.permissions
            .iter()
            .filter(|permission| {
                let mut result = permission.resource_type == resource_type &&
                    matches(action, &permission.action_id);

                if let Some(account_id) = account_id {
                    let account_id = account_id.as_ref();

                    result = result && matches(account_id, &permission.account_id);
                }

                if let Some(resource_id) = &resource_id {
                    let resource_id = resource_id.as_ref();

                    result = result && matches(resource_id, &permission.resource_id);
                }

                result

            })
            .collect();

        permissions.len() > 0
    }
}


fn matches<S: AsRef<str>>(resource: S, permission: S) -> bool {
    let resource = resource.as_ref();
    let permission = permission.as_ref();

    if (permission == "*") || (resource == permission) {
        true
    } else {
        false
    }
}


#[cfg(test)]
mod tests {
    use crate::{
        db::RolePermission,
        keys::{
            EncodingKeyPair,
            RsaPrivateKey,
        },
    };

    use super::Claims;


    #[test]
    pub fn test_claims() {
        let encoding_keys = EncodingKeyPair::try_from(
            RsaPrivateKey::new()
                .unwrap()
        ).unwrap();

        let permissions = vec![
            RolePermission {
                id: 2,
                role_id: 0,
                account_id: "*".to_owned(),
                resource_type: "accounts".to_owned(),
                resource_id: "*".to_owned(),
                action_id: "modify".to_owned(),
            }
        ];

        let expected_subject = 0;

        let claims = Claims::new(
            expected_subject,
            permissions,
        );

        let jwt = claims.into_jwt(&encoding_keys.encode)
            .unwrap();

        let validated_claims = Claims::from_jwt(jwt, &encoding_keys.decode)
            .unwrap();

        assert_eq!(validated_claims.permissions.len(), 1);
        assert_eq!(validated_claims.sub, expected_subject);
        assert_eq!(validated_claims.permissions[0].resource_type, "accounts");
    }

    #[test]
    pub fn test_claims_wildcard() {
        let permissions = vec![
            RolePermission {
                id: 2,
                role_id: 0,
                account_id: "*".to_owned(),
                resource_type: "accounts".to_owned(),
                resource_id: "*".to_owned(),
                action_id: "*".to_owned(),
            },
        ];


        let claims = Claims::new(0, permissions);

        assert!(claims.has_permission_for(Some("0"), "accounts", Some("0"), "write"));
        assert!(!claims.has_permission_for(Some("0"), "roles", Some("0"), "read"));
    }

    #[test]
    pub fn test_claims_no_permissions() {
        let permissions = vec![
            RolePermission {
                id: 2,
                role_id: 0,
                account_id: "4".to_owned(),
                resource_type: "roles".to_owned(),
                resource_id: "4".to_owned(),
                action_id: "write".to_owned(),
            },
        ];


        let claims = Claims::new(0, permissions);

        assert!(claims.has_permission_for(Some("4"), "roles", Some("4"), "write"));
        assert!(!claims.has_permission_for(Some("4"), "roles", Some("4"), "read")); // No permissions to read 4
        assert!(!claims.has_permission_for(Some("4"), "roles", Some("5"), "write")); // No permissions to write 5
        assert!(!claims.has_permission_for(Some("5"), "roles", Some("4"), "write")); // No permissions for account 5
    }

    #[test]
    pub fn test_claims_wildcard_action() {
        let permissions = vec![
            RolePermission {
                id: 2,
                role_id: 0,
                account_id: "*".to_owned(),
                resource_type: "roles".to_owned(),
                resource_id: "4".to_owned(),
                action_id: "*".to_owned(),
            },
        ];


        let claims = Claims::new(0, permissions);

        assert!(claims.has_permission_for(Some("3"), "roles", Some("4"), "write"));
        assert!(claims.has_permission_for(Some("4"), "roles", Some("4"), "read"));
        assert!(claims.has_permission_for(None, "roles", Some("4"), "write")); // Ignore account
        assert!(!claims.has_permission_for(Some("7"), "roles", Some("5"), "read")); // No permissions to read 5
        assert!(!claims.has_permission_for(Some("4"), "roles", Some("5"), "write")); // No permissions to write 5
        assert!(!claims.has_permission_for(Some("4"), "accounts", Some("4"), "read")); // No permission to read accounts
    }
}
