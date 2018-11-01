module Network.OAuth2.JWT.Client.Data (

  ) where

import           Data.Text (Text)


import           Crypto.JWT (JWK)


newtype AccessToken =
  AccessToken {
      renderAccessToken :: Text
    } deriving (Eq, Ord, Show)


data AccessTokenState =
    NoAccessToken JWK
  | HasAccessToken JWK AccessToken
