module Network.OAuth2.JWT.Client.Data (
  -- * Claims
    Issuer (..)
  , Scope (..)
  , Audience (..)
  , Subject (..)
  , Claims (..)

  -- * Configuration
  , TokenEndpoint (..)

  -- * Protocol
  , Assertion (..)
  , AccessToken (..)
  , ExpiresIn (..)
  , Response (..)

  -- * Client State
  , TokenState (..)
  , Store (..)
  , newStore
  ) where

import           Crypto.JWT (JWK)
import           Control.Concurrent.MVar (MVar)
import qualified Control.Concurrent.MVar as MVar

import qualified Data.Aeson as Aeson
import           Data.ByteString (ByteString)
import           Data.Text (Text)
import           Data.Time (NominalDiffTime, UTCTime)

import qualified Network.HTTP.Client as HTTP


-- Claims --

newtype Issuer =
  Issuer {
      getIssuer :: Text
    } deriving (Eq, Ord, Show)

newtype Scope =
  Scope {
      getScope :: Text
    } deriving (Eq, Ord, Show)

newtype Audience =
  Audience {
      getAudience :: Text
    } deriving (Eq, Ord, Show)

newtype Subject =
  Subject {
      getSubject :: Text
    } deriving (Eq, Ord, Show)

data Claims =
  Claims {
      claimsIssuer :: Issuer
    , claimsSubject :: Maybe Subject
    , claimsAudience :: Audience
    , claimsScopes :: [Scope]
    , claimsExpires :: ExpiresIn
    , claimsCustom :: [(Text, Aeson.Value)]
    } deriving (Eq, Show)


-- Configuration --

newtype TokenEndpoint =
  TokenEndpoint {
      getTokenEndpoint :: Text
    } deriving (Eq, Ord, Show)


-- Protocol --

newtype Assertion =
  Assertion {
      getAssertion :: ByteString
    } deriving (Eq, Ord, Show)

newtype AccessToken =
  AccessToken {
      renderAccessToken :: Text
    } deriving (Eq, Ord, Show)

newtype ExpiresIn =
  ExpiresIn {
      getExpiresIn :: NominalDiffTime
    } deriving (Eq, Ord, Show)

data Response =
  Response {
      responseToken :: AccessToken
    , responseExpiry :: ExpiresIn
    } deriving (Eq, Ord, Show)


-- Client State --

data TokenState =
    NoToken
  | HasToken AccessToken UTCTime

data Store =
  Store HTTP.Manager TokenEndpoint Claims JWK (MVar TokenState)

newStore :: HTTP.Manager -> TokenEndpoint -> Claims -> JWK -> IO Store
newStore manager endpoint claims jwk =
  Store manager endpoint claims jwk <$> MVar.newMVar NoToken
