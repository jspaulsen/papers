use thiserror::Error;


#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Foreign Key Constraint")]
    ForeignKeyConstraint,

    #[error("Database Error")]
    PgError(sqlx::Error),
}



impl From<sqlx::Error> for DatabaseError {
    fn from(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(err) => {
                let try_cast: Option<&sqlx::postgres::PgDatabaseError> = err
                    .try_downcast_ref();

                if let Some(cast)  = try_cast {
                    match cast.code() {
                        "23503" => {
                            Self::ForeignKeyConstraint
                        },
                        _ => Self::PgError(error)
                    }
                } else {
                    Self::PgError(error)
                }
            },
            _ => Self::PgError(error)
        }
    }
}
