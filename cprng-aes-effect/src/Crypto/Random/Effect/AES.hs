{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE StandaloneDeriving #-}
module Crypto.Random.Effect.AES
  ( runAESRNG
  ) where

import Control.Eff (Eff, SetMember, (:>))
import Control.Eff.Lift (Lift)
import Control.Eff.Reader.Strict (Reader)
import Control.Eff.State.Strict (State)
import Crypto.Random (EntropyPool)
import Crypto.Random.AESCtr (AESRNG)
import Crypto.Random.Effect (runRNG)
import Data.Typeable (Typeable)

deriving instance Typeable AESRNG

-- | Run the effect using an AES counter mode pseudo random number generator.
runAESRNG
  :: SetMember Lift (Lift IO) r
  => Eff (State AESRNG :> Reader EntropyPool :> r) a -> Eff r a
runAESRNG = runRNG
