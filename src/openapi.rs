use opg::describe_api;

use crate::{
    db::{
        Account,
        RolePermission,
    },
    schemas::{
        AccountPayload,
        JwtResponsePayload,
        RolePayload,
        RolePermissionPayload,
        RolePermissionsResponsePayload,
        RoleResponsePayload,
        TokenPayload,
    },
};


pub fn generate_opg_api<S: AsRef<str>>(version: S) -> opg::Opg {
    let version = version.as_ref();

    describe_api! {
        info: {
            title: "Papers",
            version: version,
        },
        servers: {
            "http://localhost:8080/v1",
        },
        security_schemes: {
            (http "bearerAuth"): {
                scheme: Bearer,
                bearer_format: "JWT",
            }
        },
        paths: {
            ("token"): {
                POST: {
                    summary: "Generate a JWT from api secrets",
                    description: "Exchanges API secrets for a short lived JWT used for authorization in platform services",
                    tags: {Authentication},
                    body: {
                        schema: TokenPayload,
                        required: true,
                    },
                    200: JwtResponsePayload,
                }
            },
            ("accounts"): {
                POST: {
                    summary: "Creates a new Account",
                    description: "Creates a new Account",
                    tags: {Accounts},
                    security: {"bearerAuth"},
                    body: {
                        schema: AccountPayload,
                        required: true,
                    },
                    201: Account,
                }
            },
            ("accounts" / {account_id: String}): {
                GET: {
                    summary: "Returns an account by id",
                    description: "Returns an account associated with account_id",
                    tags: {Accounts},
                    security: {"bearerAuth"},
                    200: Account,
                },
                DELETE: {
                    summary: "Deletes an account by id",
                    description: "Deletes and returns an account associated with account_id",
                    tags: {Accounts},
                    security: {"bearerAuth"},
                    200: Account,
                }
            },
            ("accounts" / {account_id: String} / "roles"): {
                POST: {
                    summary: "Creates a new Role",
                    description: "Creates a new Role within an account",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    body: {
                        schema: RolePayload,
                        required: true,
                    },
                    201: RoleResponsePayload,
                }
            },
            ("accounts" / {account_id: String} / "roles" / {role_id: String}): {
                GET: {
                    summary: "Returns a role by id",
                    description: "Returns role within a specified account by id",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    200: RoleResponsePayload,
                },
                DELETE: {
                    summary: "Deletes a role by id",
                    description: "Deletes and returns role within a specified account by id",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    200: RoleResponsePayload,
                }
            },
            ("accounts" / {account_id: String} / "roles" / {role_id: String} / "secrets"): {
                GET: {
                    summary: "Returns a roles API secrets",
                    description: "Returns the API secrets associated with a role",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    200: TokenPayload,
                },
            },
            ("accounts" / {account_id: String} / "roles" / {role_id: String} / "secrets" / "regenerate"): {
                POST: {
                    summary: "Regenerates secret key for a role",
                    description: "Regenerates secret key for a role",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    204: (),
                },
            },
            ("accounts" / {account_id: String} / "roles" / {role_id: String} / "permissions"): {
                POST: {
                    summary: "Creates a new permission within a Role",
                    description: "Creates a new RolePermission within a Role",
                    tags: {RolePermission},
                    security: {"bearerAuth"},
                    body: {
                        schema: RolePermissionPayload,
                        required: true,
                    },
                    201: RolePermission,
                },
                GET: {
                    summary: "Returns all RolePermissions for a given role",
                    description: "Returns all RolePermissions for a given role",
                    tags: {RolePermission},
                    security: {"bearerAuth"},
                    200: RolePermissionsResponsePayload,
                },
            },
            ("accounts" / {account_id: String} / "roles" / {role_id: String} / "permissions" / {permission_id: String}): {
                GET: {
                    summary: "Returns a RolePermission by id",
                    description: "Return a RolePermission within a specified account and role by id",
                    tags: {RolePermission},
                    security: {"bearerAuth"},
                    200: RolePermission,
                },
                DELETE: {
                    summary: "Returns a RolePermission by id",
                    description: "Delete and returns a RolePermission within a specified account and role by id",
                    tags: {Roles},
                    security: {"bearerAuth"},
                    200: RolePermission,
                }
            },
        },
    }
}
