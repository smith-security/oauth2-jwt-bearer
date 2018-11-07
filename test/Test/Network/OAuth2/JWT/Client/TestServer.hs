{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Test.Network.OAuth2.JWT.Client.TestServer (
    good
  , good3600
  , bad
  , withServer
  , withServerIO
  ) where

import           Control.Exception (bracket)
import qualified Control.Concurrent.Async as Async
import           Control.Monad.IO.Class (MonadIO (..))

import           Data.IORef (IORef)
import qualified Data.IORef as IORef
import           Data.Text (Text)
import qualified Data.Text as Text
import           Data.Aeson ((.=))
import qualified Data.Aeson as Aeson
import qualified Data.Streaming.Network as Network

import           Hedgehog

import           Network.OAuth2.JWT.Client
import qualified Network.Socket as Socket
import qualified Network.Wai.Handler.Warp as Warp

import qualified Network.HTTP.Types as HTTP

import qualified Web.Spock.Core as Spock

good :: Int -> Text -> (HTTP.Status, Aeson.Value)
good expires token =
  (HTTP.status200, Aeson.object [
      "token_type" .= ("Bearer" :: Text)
    , "expires_in" .= expires
    , "access_token" .= token
    ])

good3600 :: (HTTP.Status, Aeson.Value)
good3600 =
  good 3600 "default-token-3600"

bad :: (HTTP.Status, Aeson.Value)
bad =
  (HTTP.status400, Aeson.object [
      "error" .= ("invalid_grant" :: Text)
    ])

routes :: IORef [(HTTP.Status, Aeson.Value)] -> Spock.SpockT IO ()
routes responses = do
  Spock.post "oauth/token" $ do
    mflow <- Spock.param "grant_type"
    massertion <- Spock.param "assertion"
    case (massertion, mflow) of
      (Just _assertion, Just "urn:ietf:params:oauth:grant-type:jwt-bearer") -> do
        (status, response) <- liftIO $ IORef.atomicModifyIORef responses $ \rs -> case rs of
          [] ->
            ([], good3600)
          (x:xs) ->
            (xs, x)
        Spock.setStatus status
        Spock.json response
      (_ :: Maybe Text, _ :: Maybe Text) -> do
        Spock.setStatus HTTP.status400
        Spock.json $ Aeson.object [
            "error" .= ("invalid_grant" :: Text)
          ]

withServer :: (MonadIO m, MonadTest m) => [(HTTP.Status, Aeson.Value)] -> (TokenEndpoint -> IO a) -> m a
withServer responses =
  evalIO . withServerIO responses

withServerIO :: [(HTTP.Status, Aeson.Value)] -> (TokenEndpoint -> IO a) -> IO a
withServerIO responses testing = do
  r <- IORef.newIORef responses
  app <- Spock.spockAsApp $ Spock.spockConfigT Spock.defaultSpockConfig id (routes r)
  Socket.withSocketsDo $
    bracket
      (Network.bindPortTCP 0 "127.0.0.1")
      Socket.close
      (\socket -> do
        name <- Socket.getSocketName socket
        case name of
          Socket.SockAddrInet port _ -> do
            Async.withAsync (Warp.runSettingsSocket Warp.defaultSettings socket app) $ \_ -> do
              testing . TokenEndpoint . mconcat $ ["http://localhost:", Text.pack . show $ port, "/oauth/token"]
          _ -> do
            error "<invariant> forcing inet above.")
