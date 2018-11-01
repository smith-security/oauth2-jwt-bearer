{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE TemplateHaskell #-}
module Test.Network.OAuth2.JWT.Client.AuthorizationGrant where

import           Hedgehog

import           Prelude (($), Bool (..))

import           Network.OAuth2.JWT.Client.AuthorizationGrant

import           System.IO (IO)


prop_placeholder :: Property
prop_placeholder =
  property $
    1 === 1

tests :: IO Bool
tests =
  checkParallel $$(discover)
