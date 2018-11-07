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
