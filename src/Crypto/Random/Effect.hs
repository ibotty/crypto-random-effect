{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeOperators #-}
-- | A Random effect.
--
-- Any ideas to let the user specify the random number generator ('C.CPRG')
-- instead of hardcoding 'C.SystemRNG' without complicating the api and
-- reinventing state as 'SetMember' is very welcome.
module Crypto.Random.Effect
  ( RNG()
  , runRNG
  , runRNGWithPool
  , withRNG
  , withRNGIO
  , rngFork
  , randomBytes
  , randomBytesWithEntropy
  , withRandomBytes
  , createEntropyPool
  , grabEntropy
  , unsafeGrabEntropy
  -- | reexports from 'crypto-random'
  , C.CPRG()
  , C.SystemRNG()
  , C.EntropyPool()
  ) where

import Control.Eff
import Control.Eff.Lift
import Control.Eff.State.Strict
import Control.Eff.Reader.Strict
import Data.ByteString (ByteString)
import Data.SecureMem (SecureMem)
import Data.Typeable (Typeable)
import qualified Crypto.Random as C

type RNG = State C.SystemRNG

deriving instance Typeable C.SystemRNG
deriving instance Typeable C.EntropyPool

-- | Run the effect.
runRNG
  :: SetMember Lift (Lift IO) r
  => Eff (RNG :> Reader C.EntropyPool :> r) a -> Eff r a
runRNG e = lift C.createEntropyPool >>= flip runRNGWithPool e

runRNGWithPool
  :: SetMember Lift (Lift IO) r
  => C.EntropyPool -> Eff (RNG :> Reader C.EntropyPool :> r) a -> Eff r a
runRNGWithPool pool = flip runReader pool . evalState (C.cprgCreate pool)

withRNG :: Member RNG r => (C.SystemRNG -> Eff r (a, C.SystemRNG)) -> Eff r a
withRNG f = do
    rng <- get
    (a, rng') <- f rng
    put rng'
    return a

withRNGPure :: Member RNG r => (C.SystemRNG -> (a, C.SystemRNG)) -> Eff r a
withRNGPure f = withRNG (return . f)

withRNGIO
  :: (SetMember Lift (Lift IO) r, Member RNG r)
  => (C.SystemRNG -> IO (a, C.SystemRNG)) -> Eff r a
withRNGIO f = withRNG (lift . f)

rngFork :: Member RNG r => Eff r C.SystemRNG
rngFork = withRNGPure C.cprgFork

randomBytes :: Member RNG r => Int -> Eff r ByteString
randomBytes = withRNGPure . C.cprgGenerate

randomBytesWithEntropy :: Member RNG r => Int -> Eff r ByteString
randomBytesWithEntropy = withRNGPure . C.cprgGenerateWithEntropy

withRandomBytes :: Member RNG r => Int -> (ByteString -> Eff r a) -> Eff r a
withRandomBytes cnt f = randomBytes cnt >>= f

createEntropyPool :: SetMember Lift (Lift IO) r => Eff r C.EntropyPool
createEntropyPool = lift C.createEntropyPool

grabEntropy
  :: (SetMember Lift (Lift IO) r, Member (Reader C.EntropyPool) r)
  => Int -> Eff r SecureMem
grabEntropy cnt = ask >>= lift . C.grabEntropyIO cnt

unsafeGrabEntropy :: Member (Reader C.EntropyPool) r => Int -> Eff r SecureMem
unsafeGrabEntropy cnt = fmap (C.grabEntropy cnt) ask
