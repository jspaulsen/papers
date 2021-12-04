CREATE TABLE IF NOT EXISTS root_account_singleton (
    -- entity_id SERIAL NOT NULL,
    account_id SERIAL NOT NULL,
    role_id SERIAL NOT NULL,
    single_row bool NOT NULL DEFAULT TRUE UNIQUE CHECK (single_row)
);


-- List of accounts
CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    description TEXT NOT NULL
);


-- List of roles
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    account_id SERIAL NOT NULL,
    description TEXT NOT NULL,
    api_token TEXT NOT NULL,

    CONSTRAINT fk_account
        FOREIGN KEY(account_id)
            REFERENCES accounts(id)
            ON DELETE CASCADE
);


-- List of entities
-- CREATE TABLE IF NOT EXISTS entities (
--     id SERIAL PRIMARY KEY,
--     account_id SERIAL NOT NULL,
--     role_id SERIAL,

--     CONSTRAINT fk_role
--         FOREIGN KEY(role_id)
--             REFERENCES roles(id)
--             ON DELETE CASCADE,

--     CONSTRAINT fk_account
--         FOREIGN KEY(account_id)
--             REFERENCES accounts(id)
--             ON DELETE CASCADE
-- );


-- List of permissions for roles
CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL NOT NULL,
    role_id SERIAL NOT NULL,
    account_id TEXT NOT NULL, -- id (or wildcard) of applicable account resources
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL, -- id on corresponding resource table
    action_id TEXT NOT NULL, -- Ex. invoke_function

    CONSTRAINT fk_role
        FOREIGN KEY(role_id)
            REFERENCES roles(id)
            ON DELETE CASCADE,

    PRIMARY KEY (role_id, resource_type, resource_id, action_id)
);


-- Setup initial root account, role and entity
INSERT INTO accounts (description) VALUES ('Root platform account');
INSERT INTO roles (account_id, description, api_token) SELECT accounts.id, 'Root account role', gen_random_uuid() FROM accounts;
--INSERT INTO entities (account_id, role_id) SELECT MIN(accounts.id), MIN(roles.id) FROM accounts, roles;
INSERT INTO root_account_singleton (role_id, account_id, single_row) SELECT MIN(roles.id), MIN(accounts.id), true FROM roles, accounts;

-- Role Permissions
INSERT INTO role_permissions (role_id, account_id, resource_type, resource_id, action_id) SELECT MIN(roles.id), '*', 'accounts', '*', '*' from roles;
INSERT INTO role_permissions (role_id, account_id, resource_type, resource_id, action_id) SELECT MIN(roles.id), '*', 'roles', '*', '*' from roles;

