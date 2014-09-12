-- | An effect that can generate random bytes.
--
-- It is essentially a 'State' monad with a given 'CPRG'.
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
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
  -- * Re-exports
  , CPRG()
  , SystemRNG()
  , EntropyPool()
  ) where

import Control.Applicative ((<$>))
import Control.Eff
import Control.Eff.Lift
import Control.Eff.State.Strict
import Control.Eff.Reader.Strict
import Data.ByteString (ByteString)
import Data.SecureMem (SecureMem)
import Crypto.Random (CPRG, EntropyPool, SystemRNG)
import qualified Crypto.Random as C

-- | Type marker to ensure that there is only one RNG.
data RNG

instance SetMember RNG (State gen) (State gen :> a)

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

-- | Run the effect with a given 'EntropyPool'.
runRNGWithPool
  :: (SetMember Lift (Lift IO) r, Typeable gen, CPRG gen)
  => EntropyPool -> Eff (State gen :> Reader EntropyPool :> r) a -> Eff r a
runRNGWithPool pool = flip runReader pool . evalState (C.cprgCreate pool)

-- | Wrap an effect that uses the 'CPRG' directly.
withRNG :: (SetMember RNG (State gen) r, Typeable gen) => (gen -> Eff r (a, gen)) -> Eff r a
withRNG f = do
    rng <- get
    (a, rng') <- f rng
    put rng'
    return a

-- | Wrap a pure function that uses the 'CPRG' directly.
withRNGPure :: (SetMember RNG (State gen) r, Typeable gen) => (gen -> (a, gen)) -> Eff r a
withRNGPure f = withRNG (return . f)

-- | Wrap an IO action that uses the 'CPRG' directly.
withRNGIO
  :: (SetMember Lift (Lift IO) r, SetMember RNG (State gen) r, Typeable gen)
  => (gen -> IO (a, gen)) -> Eff r a
withRNGIO f = withRNG (lift . f)

-- | Fork a CPRG into a new independent CPRG.
--
-- As entropy is mixed to generate safely a new generator, 2 calls with the
-- same CPRG will not produce the same output.
rngFork :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Eff r gen
rngFork = withRNGPure C.cprgFork

-- | Generate a number of bytes using the CPRG.
randomBytes :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> Eff r ByteString
randomBytes = withRNGPure . C.cprgGenerate

-- | Similar to 'randomBytes' except that the random data is mixed with pure
-- entropy, so the result is not reproducible after use, but it provides
-- more guarantee, theorically speaking, in term of the randomness
-- generated.
randomBytesWithEntropy :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> Eff r ByteString
randomBytesWithEntropy = withRNGPure . C.cprgGenerateWithEntropy

-- | Consume a number of random bytes with a pure function.
--
-- Note, that this is simply
--
-- > randomBytes cnt >>= return . f
withRandomBytes :: (SetMember RNG (State gen) r, CPRG gen, Typeable gen) => Int -> (ByteString -> a) -> Eff r a
withRandomBytes cnt f = f <$> randomBytes cnt

-- Create a new entropy pool.
createEntropyPool :: SetMember Lift (Lift IO) r => Eff r EntropyPool
createEntropyPool = lift C.createEntropyPool

-- | Grab a chunk of entropy from the entropy pool.
grabEntropy
  :: (SetMember Lift (Lift IO) r, Member (Reader EntropyPool) r)
  => Int -> Eff r SecureMem
grabEntropy cnt = ask >>= lift . C.grabEntropyIO cnt

-- | Grab a chunk of entropy from the entropy pool.
--
-- Beware: uses unsafePerformIO under the hood.
unsafeGrabEntropy :: Member (Reader EntropyPool) r => Int -> Eff r SecureMem
unsafeGrabEntropy cnt = fmap (C.grabEntropy cnt) ask
