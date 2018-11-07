-- |
-- Example, this is mainly for ensuring example compiles. You probably
-- want 'Network.OAuth2.JWT.Client'.
--
{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.JWT.Client.Example where

import           Crypto.JWT (JWK)
import           Network.OAuth2.JWT.Client
import           Network.HTTP.Client (Manager)


example :: Manager -> JWK -> IO (Either GrantError AccessToken)
example manager key =  do
  let
    endpoint = TokenEndpoint "https://www.googleapis.com/oauth2/v4/token"
    iss = Issuer "example@example.org"
    scopes = [Scope "profile"]
    aud = Audience "https://www.googleapis.com/oauth2/v4/token"
    expiry = ExpiresIn 3600
    claims = Claims iss Nothing aud scopes expiry []
  store <- newStore manager endpoint claims key
  grant store
