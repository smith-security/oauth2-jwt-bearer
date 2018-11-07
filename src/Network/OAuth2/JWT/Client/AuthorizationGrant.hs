{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.JWT.Client.AuthorizationGrant (
    GrantError (..)
  , sign
  , refresh
  , local
  , grant
  ) where


import qualified Control.Concurrent.MVar as MVar
import           Control.Lens ((.~), (&))
import           Control.Monad.IO.Class (MonadIO (..))
import           Control.Monad.Trans.Bifunctor (BifunctorTrans (..))
import           Control.Monad.Trans.Except (ExceptT (..), runExceptT)

import           Crypto.JWT (JWK, JWTError)
import qualified Crypto.JWT as JWT

import qualified Data.Aeson as Aeson
import           Data.Bifunctor as X (Bifunctor(..))
import qualified Data.ByteString.Lazy as LazyByteString
import qualified Data.HashMap.Strict as HashMap
import           Data.String (IsString (..))
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import           Data.Time (UTCTime)
import qualified Data.Time as Time

import           Network.OAuth2.JWT.Client.Data
import qualified Network.OAuth2.JWT.Client.Serial as Serial

import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Types as HTTP

data GrantError =
    SerialisationGrantError Text
  | JWTGrantError JWT.JWTError
  | EndpointGrantError Text
  | StatusGrantError Int Text
    deriving (Eq, Show)

-- |
-- Obtain an access token, if we have already aquired one (and
-- it is still valid) we will re-use that token, if we don't
-- already have a token or the token has expired, we go and
-- ask for a new one.
--
-- This operation is safe to call from multiple threads. If we are
-- using a current token reads will happen concurrently, If we have to
-- go to the network the request will be serialised so that only one
-- request is made for a new token.
--
grant :: Store -> IO (Either GrantError AccessToken)
grant (Store manager endpoint claims jwk store) = do
  now <- Time.getCurrentTime
  t <- local now <$> MVar.readMVar store
  case t of
    Just token ->
      pure . Right $ token
    Nothing -> do
      MVar.modifyMVar store $ \state -> do
        case local now state of
          Just token ->
            pure (state, Right token)
          Nothing ->
            runExceptT (refresh now manager endpoint claims jwk) >>= \e -> case e of
               Left err ->
                 pure (state, Left err)
               Right (Response token expiry) ->
                 pure (HasToken token (Time.addUTCTime (getExpiresIn expiry) now), Right token)

-- |
-- Obtain an already aquired access token iff it is still valid.
--
local :: UTCTime -> TokenState -> Maybe AccessToken
local now state =
  case state of
    HasToken token time | now < time ->
      Just token
    HasToken _ _ ->
      Nothing
    NoToken ->
      Nothing

-- |
-- Request a new access token as per the specified claims.
--
-- This request is defined in <https://tools.ietf.org/html/rfc7523#section-2.1 2.1> of
-- <https://tools.ietf.org/html/rfc7523#section-2.1 rfc7523>.
--
refresh :: UTCTime -> HTTP.Manager -> TokenEndpoint -> Claims -> JWK -> ExceptT GrantError IO Response
refresh now manager endpoint claims jwk = do
  assertion <- firstT JWTGrantError $
    sign now claims jwk
  req <- ExceptT . pure . first (EndpointGrantError . Text.pack . show) $
    HTTP.parseRequest (Text.unpack . getTokenEndpoint $ endpoint)
  res <- liftIO $ flip HTTP.httpLbs manager $
    HTTP.urlEncodedBody [
        ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
      , ("assertion", getAssertion assertion)
      ] $ req { HTTP.requestHeaders = [
        ("Accept", "application/json")
      ] }
  case HTTP.statusCode . HTTP.responseStatus $ res of
    200 ->
      ExceptT . pure . first SerialisationGrantError $
        Serial.response (HTTP.responseBody res)
    status ->
      ExceptT . pure . Left $ StatusGrantError status (Text.decodeUtf8 . LazyByteString.toStrict . HTTP.responseBody $ res)

-- |
-- Sign a JWT with the specified claims and key.
--
-- The format and signature of the JWT are defined by
-- <https://tools.ietf.org/html/rfc7519 rfc7519>.
--
-- The specific of the claims are defined by the OAuth2
-- JWT Profile <https://tools.ietf.org/html/rfc7523 rfc7523>.
--
sign :: UTCTime -> Claims -> JWK -> ExceptT JWTError IO Assertion
sign now (Claims issuer subject audience scopes expires custom) jwk = do
  let
    format =
      fromString . Text.unpack

    header =
      JWT.newJWSHeader ((), JWT.RS256)
        & JWT.typ .~ Just (JWT.HeaderParam () "JWT")

    claims =
      JWT.emptyClaimsSet
        & JWT.claimIss .~ Just (format . getIssuer $ issuer)
        & JWT.claimSub .~ fmap (format . getSubject) subject
        & JWT.claimAud .~ Just (JWT.Audience [format . getAudience $ audience])
        & JWT.claimIat .~ Just (JWT.NumericDate now)
        & JWT.claimExp .~ Just (JWT.NumericDate $ Time.addUTCTime (getExpiresIn expires) now)
        & JWT.unregisteredClaims .~ (HashMap.fromList $ [
            ("scope", Aeson.toJSON . Text.intercalate " " $ getScope <$> scopes)
          ] ++ custom)

  signed <- JWT.signClaims jwk header claims
  pure . Assertion . LazyByteString.toStrict . JWT.encodeCompact $ signed
