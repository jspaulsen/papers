use std::ops::Deref;


pub enum ResourceType {
    Roles,
    Accounts,
}


pub enum ResourceActions {
    Create,
    Delete,
    Modify,
    Read,
}


impl Deref for ResourceType {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            ResourceType::Roles => "roles",
            ResourceType::Accounts => "accounts"
        }
    }
}


impl Deref for ResourceActions {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        match self {
            ResourceActions::Create => "create",
            ResourceActions::Delete => "delete",
            ResourceActions::Modify => "modify",
            ResourceActions::Read => "read",
        }
    }
}


impl AsRef<str> for ResourceType {
    fn as_ref(&self) -> &str {
        match self {
            ResourceType::Roles => "roles",
            ResourceType::Accounts => "accounts",
        }
    }
}


impl AsRef<str> for ResourceActions {
    fn as_ref(&self) -> &str {
        match self {
            ResourceActions::Create => "create",
            ResourceActions::Delete => "delete",
            ResourceActions::Modify => "modify",
            ResourceActions::Read => "read",
        }
    }
}
