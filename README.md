# Papers, Access Management Service

Papers is a rudimentary "Identity" and Access Management service;  access to systems is done via Role API secrets.

## Authentication

Authentication is done via api secrets signed by the HMAC_SECRET_KEY.  Each role is given a role_id and an API secret in which to authenticate via `/token`,
which provides a short-lived JWT with a list of permissions for the role

## Roles

Roles are the mechanism authorized access to services is done.

### Role Permissions

Role permissions are scoped by account_id and resource_type and resource_id, with an an "action_id" defining the action the role can perform on that resource.
Role permissions can have wildcards (`*`) for `account_id`, `resource_id` and `action_id` allowing for flexibility in grants.


Example:

```json
{
    "account_id": "*",
    "resource_type": "roles",
    "action_id": "read"
}
```

Access to role `write` permissions within an account should be limited.

## Setup
### Initialization

If no RSA keys (used for JWT signing) exist in the data directory, `papers` will generate a new key pair.

## Environment
## Required

* `DATABASE_URI` - Postgres database URL; refer to [this](https://docs.rs/sqlx/latest/sqlx/postgres/struct.PgConnectOptions.html) for structure
* `HMAC_SECRET_KEY` - Hex string of 64 digits used to encrypt API tokens

## Optional

* `APP_DATA_DIR` - Application data directory, defaults to `/var/libs/papers`
* `HTTP_PORT` - Port which server listens on; defaults to `8080`
* `HTTP_BIND_ADDRESS` - Address on which server listens on; defaults to `0.0.0.0`
- `LOG_LEVEL` - Defines the level at (or above) which messages are logged.

### Postgres

Any PG configuration not populated in the `DATABASE_URI` can be provided via PG specific environment variables:

* `PGHOST`
* `PGPORT`
* `PGUSER`
* `PGPASSWORD`
* `PGDATABASE`
* `PGSSLROOTCERT`
* `PGSSLMODE`
* `PGAPPNAME`

### Danger
* `REISSUE_ROOT_SECRETS` - if true, `Papers` will load and generate a secrets file within the application data directory.  This is generally only useful on first run or if regenerating the root account `api_token`.

## Development
### Testing

Tests can be run via `cargo test` or `./test.sh`; `ingored` tests require a live database and can be tested via the `--database` flag, i.e., `./test.sh --database`

