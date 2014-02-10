-- | A Random effect.
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeOperators #-}
module Crypto.Random.Effect
  ( RNG
  , runSystemRNG
  , runRNGWithPool
  , runRNG
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
  , CPRG()
  , SystemRNG()
  , EntropyPool()
  ) where

import Control.Eff
import Control.Eff.Lift
import Control.Eff.State.Strict
import Control.Eff.Reader.Strict
import Data.ByteString (ByteString)
import Data.SecureMem (SecureMem)
import Data.Typeable (Typeable)
import Crypto.Random (CPRG, EntropyPool, SystemRNG)
import qualified Crypto.Random as C

data RNG

instance SetMember RNG (State gen) (State gen :> a) where

deriving instance Typeable SystemRNG
deriving instance Typeable EntropyPool

-- | Run the effect using 'SystemRNG'.
runSystemRNG
  :: SetMember Lift (Lift IO) r
  => Eff (State SystemRNG :> Reader EntropyPool :> r) a -> Eff r a
runSystemRNG = runRNG

-- | Run the effect without specifying the 'CPRG'.
--
-- This is only useful when the type of the 'CPRG' is bound by an explicit
-- type annotation (see 'runSystemRNG' which is 'runRNG' with bound type)
-- or any function within the effect binds it.
runRNG :: (SetMember Lift (Lift IO) r, Typeable gen, CPRG gen)
  => Eff (State gen :> Reader EntropyPool :> r) a -> Eff r a
runRNG e = createEntropyPool >>= flip runRNGWithPool e

runRNGWithPool
  :: (SetMember Lift (Lift IO) r, Typeable gen, CPRG gen)
  => EntropyPool -> Eff (State gen :> Reader EntropyPool :> r) a -> Eff r a
runRNGWithPool pool = flip runReader pool . evalState (C.cprgCreate pool)

withRNG :: (SetMember RNG (State gen) r, Typeable gen) => (gen -> Eff r (a, gen)) -> Eff r a
withRNG f = do
    rng <- get
    (a, rng') <- f rng
    put rng'
    return a

withRNGPure :: (SetMember RNG (State gen) r, Typeable gen) => (gen -> (a, gen)) -> Eff r a
withRNGPure f = withRNG (return . f)

withRNGIO
  :: (SetMember Lift (Lift IO) r, SetMember RNG (State gen) r, Typeable gen)
  => (gen -> IO (a, gen)) -> Eff r a
withRNGIO f = withRNG (lift . f)

rngFork :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Eff r gen
rngFork = withRNGPure C.cprgFork

randomBytes :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> Eff r ByteString
randomBytes = withRNGPure . C.cprgGenerate

randomBytesWithEntropy :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> Eff r ByteString
randomBytesWithEntropy = withRNGPure . C.cprgGenerateWithEntropy

withRandomBytes :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> (ByteString -> Eff r a) -> Eff r a
withRandomBytes cnt f = randomBytes cnt >>= f

createEntropyPool :: SetMember Lift (Lift IO) r => Eff r EntropyPool
createEntropyPool = lift C.createEntropyPool

grabEntropy
  :: (SetMember Lift (Lift IO) r, Member (Reader EntropyPool) r)
  => Int -> Eff r SecureMem
grabEntropy cnt = ask >>= lift . C.grabEntropyIO cnt

unsafeGrabEntropy :: Member (Reader EntropyPool) r => Int -> Eff r SecureMem
unsafeGrabEntropy cnt = fmap (C.grabEntropy cnt) ask

t = runLift $ runRNG $ withRNG f
  -- where f :: CPRG gen => gen -> Eff r (Int, gen)
  where f :: SystemRNG -> Eff r (Int, SystemRNG)
        f g = return (2, g)
