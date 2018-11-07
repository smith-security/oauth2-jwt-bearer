-- |
-- Serialisation of token response. You probably want 'Network.OAuth2.JWT.Client'.
--
{-# LANGUAGE OverloadedStrings #-}
module Network.OAuth2.JWT.Client.Serial (
    response
  , parser
  ) where

import           Control.Monad (when)

import           Data.Aeson ((.:))
import qualified Data.Aeson as Aeson
import qualified Data.Aeson.Types as Aeson
import           Data.Bifunctor as X (Bifunctor(..))
import qualified Data.ByteString.Lazy as LazyByteString
import           Data.Text (Text)
import qualified Data.Text as Text

import           Network.OAuth2.JWT.Client.Data


response :: LazyByteString.ByteString -> Either Text Response
response bytes =
  first Text.pack (Aeson.eitherDecode bytes) >>= \a' -> case Aeson.parse parser a' of
    Aeson.Success a -> pure a
    Aeson.Error msg -> Left . Text.pack $ msg

parser :: Aeson.Value -> Aeson.Parser Response
parser =
  Aeson.withObject "Response" $ \o ->
    Response
      <$> (fmap AccessToken $ o .: "access_token")
      <*> (fmap ExpiresIn $ o .: "expires_in")
      <* (o .: "token_type" >>= tokenType)

tokenType :: Text -> Aeson.Parser ()
tokenType t =
  when (t /= "Bearer") $
    fail "Unknown 'token_type' expected: 'Bearer'."
