-- |
--
-- This is an implementation of the jwt-bearer authorization grant
-- flow that is specified by the OAuth2 JWT profile in
-- <https://tools.ietf.org/html/rfc7523 rfc7523>.
--
-- This module includes everything you should need to implement an
-- integration and obtain an access token.
--
-- > {-# LANGUAGE OverloadedStrings #-}
-- >
-- > import           Crypto.JWT (JWK)
-- > import           Network.OAuth2.JWT.Client
-- > import           Network.HTTP.Client (Manager)
--
-- The key function here is the 'grant' function which is what you call
-- to get your access token.
--
-- The 'grant' function obtains an access token, if we have already
-- aquired one (and it is still valid) we will re-use that token, if we
-- don't already have a token or the token has expired, we go and ask for
-- a new one.
--
-- > example :: Manager -> JWK -> IO (Either GrantError AccessToken)
-- > example manager key =  do
-- >   let
-- >     endpoint = TokenEndpoint "https://www.googleapis.com/oauth2/v4/token"
-- >     iss = Issuer "example@example.org"
-- >     scopes = [Scope "profile"]
-- >     aud = Audience "https://www.googleapis.com/oauth2/v4/token"
-- >     expiry = ExpiresIn 3600
-- >     claims = Claims iss Nothing aud scopes expiry []
-- >   store <- newStore manager endpoint claims key
-- >   grant store
--
-- This operation is safe to call from multiple threads. If we are using
-- a current token reads will happen concurrently, If we have to go to
-- the network the request will be serialised so that only one request is
-- made for a new token.
--
-- The access token can be used as a bearer token in an @Authorization@
-- header. See the specification for more details but it would be something
-- like:
--
-- @
-- Authorization: Bearer ${ACCESS_TOKEN}
-- @
--
--
module Network.OAuth2.JWT.Client (
  -- * Obtain an access token
    GrantError (..)
  , AccessToken (..)
  , grant

  -- * Claims
  , Issuer (..)
  , Scope (..)
  , Audience (..)
  , Subject (..)
  , ExpiresIn (..)
  , Claims (..)

  -- * Configuration
  , TokenEndpoint (..)
  , Store
  , newStore
  ) where

import Network.OAuth2.JWT.Client.Data
import Network.OAuth2.JWT.Client.AuthorizationGrant
