use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub name: String,
    pub email: String,
    pub exp: i64,
    pub iat: String,
}

pub fn generate_token(name: String, email: String) -> Result<String, Error> {
    let exp = Utc::now()
        .checked_add_signed(Duration::days(1))
        .expect("valid timestamp")
        .timestamp();
    let claims = Claims {
        name,
        email,
        exp,
        iat: Utc::now().to_string(),
    };
    let header = Header::new(Algorithm::HS512);
    let password = "somePasswordLong";
    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_secret(password.as_ref()),
    );
    token
    //  header;claims;hash
}

pub fn validate_token(token: String) -> Result<jsonwebtoken::TokenData<Claims>, Error> {
    let token_message = decode::<Claims>(
        &token,
        &DecodingKey::from_secret("somePasswordLong".as_ref()),
        &Validation::new(Algorithm::HS512),
    );
    token_message
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() -> Result<(), ()> {
        let example_token = generate_token("Nithin".into(), "fsd.com".into());

        println!("Encoded Token : {:?}", example_token);
        assert_eq!(example_token.is_ok(), true);
        assert_eq!(example_token.is_ok(), true);

        match example_token {
            Ok(token) => match validate_token(token.into()) {
                Ok(claims) => {
                    println!("Decoded token :{:?}", claims);
                    Ok(())
                }
                Err(err) => {
                    println!("token failed {:?}", err);
                    panic!("token filed");
                }
            },
            _ => Err(()),
        }
    }
}
