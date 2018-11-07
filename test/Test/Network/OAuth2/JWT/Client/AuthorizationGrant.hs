{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TemplateHaskell #-}
module Test.Network.OAuth2.JWT.Client.AuthorizationGrant where

import           Control.Monad.IO.Class (MonadIO (..))

import qualified Crypto.JWT as JWT
import qualified Crypto.PubKey.RSA as Cryptonite

import           Data.Aeson ((.:))
import qualified Data.Aeson as Aeson
import qualified Data.ByteString as ByteString
import qualified Data.Maybe as Maybe
import           Data.Text (Text)
import qualified Data.Text as Text
import qualified Data.Text.Encoding as Text
import qualified Data.Text.IO as Text
import qualified Data.X509 as X509
import qualified Data.X509.Memory as X509

import           Hedgehog

import           Network.OAuth2.JWT.Client
import qualified Network.HTTP.Client.TLS as HTTP
import qualified Network.HTTP.Client as HTTP

import           System.IO (IO)
import qualified System.Environment as Environment

import qualified Test.Network.OAuth2.JWT.Client.TestServer as TestServer


prop_success :: Property
prop_success =
  withTests 1 . property $ do
    token <- TestServer.withServer [] $ \endpoint -> do
      (_public, private) <- Cryptonite.generate 512 0x10001
      manager <- HTTP.newManager HTTP.tlsManagerSettings
      let
        iss = Issuer "iss"
        scopes = [Scope "profile"]
        aud = Audience "aud"
        expiry = ExpiresIn 3600
        claims = Claims iss Nothing aud scopes expiry []
        jwk = JWT.fromRSA private
      store <- newStore manager endpoint claims jwk
      grant store
    token === Right (AccessToken "default-token-3600")

prop_cache :: Property
prop_cache =
  withTests 1 . property $ do
    (token1, token2) <- TestServer.withServer [TestServer.good 3600 "a", TestServer.good 3600 "b"] $ \endpoint -> do
      (_public, private) <- Cryptonite.generate 512 0x10001
      manager <- HTTP.newManager HTTP.tlsManagerSettings
      let
        iss = Issuer "iss"
        scopes = [Scope "profile"]
        aud = Audience "aud"
        expiry = ExpiresIn 3600
        claims = Claims iss Nothing aud scopes expiry []
        jwk = JWT.fromRSA private
      store <- newStore manager endpoint claims jwk
      (,) <$> grant store <*> grant store
    token1 === Right (AccessToken "a")
    token1 === token2

prop_refresh :: Property
prop_refresh =
  withTests 1 . property $ do
    (token1, token2) <- TestServer.withServer [TestServer.good 0 "a", TestServer.good 3600 "b"] $ \endpoint -> do
      (_public, private) <- Cryptonite.generate 512 0x10001
      manager <- HTTP.newManager HTTP.tlsManagerSettings
      let
        iss = Issuer "iss"
        scopes = [Scope "profile"]
        aud = Audience "aud"
        expiry = ExpiresIn 0
        claims = Claims iss Nothing aud scopes expiry []
        jwk = JWT.fromRSA private
      store <- newStore manager endpoint claims jwk
      (,) <$> grant store <*> grant store
    token1 === Right (AccessToken "a")
    token2 === Right (AccessToken "b")

data ServiceAccountKey =
  ServiceAccountKey {
      clientEmail :: Text
    , clientId :: Text
    , privateKeyId :: Text
    , privateKey :: Text
    } deriving (Eq, Ord, Show)

instance Aeson.FromJSON ServiceAccountKey where
  parseJSON =
    Aeson.withObject "ServiceAccountKey" $ \o ->
      ServiceAccountKey
        <$> o .: "client_email"
        <*> o .: "client_id"
        <*> o .: "private_key_id"
        <*> o .: "private_key"

prop_google :: Property
prop_google =
  withTests 1 . property $ do
    e <- liftIO $ Environment.lookupEnv "GOOGLE_CREDENTIALS_JSON"
    case e of
      Nothing ->
        success
      Just file -> do
        manager <- liftIO $ HTTP.newManager HTTP.tlsManagerSettings
        blob <- liftIO $ ByteString.readFile file
        key <- evalEither  $ Aeson.eitherDecodeStrict blob
        jwk <- case Maybe.listToMaybe . X509.readKeyFileFromMemory . Text.encodeUtf8 . privateKey $ key of
          Just (X509.PrivKeyRSA k) ->
            pure $ JWT.fromRSA k
          _ ->
            failure
        let
          endpoint = TokenEndpoint "https://www.googleapis.com/oauth2/v4/token"
          iss = Issuer (clientEmail key)
          scopes = [Scope "profile"]
          aud = Audience "https://www.googleapis.com/oauth2/v4/token"
          expiry = ExpiresIn 3600
          claims = Claims iss Nothing aud scopes expiry []
        store <- liftIO $ newStore manager endpoint claims jwk
        token <- liftIO (grant store) >>= evalEither
        liftIO $
          Text.putStrLn "=== BEGIN TOKEN ==="
        liftIO $
          Text.putStrLn . Text.pack . show $ token
        liftIO $
          Text.putStrLn "=== END TOKEN ==="


tests :: IO Bool
tests =
  checkParallel $$(discover)
