//! Driving `beekem`'s `async fn`s to completion without an async runtime.
//!
//! `beekem::cgka::Cgka` exposes `add`, `remove`, `update` and `new_app_secret_for`
//! as `async fn`s generic over `future_form::FutureForm`, because a real
//! deployment may hold its signing key in a hardware token or a browser
//! `CryptoKey` and therefore has to `await` each signature.
//!
//! We do not. [`keyhive_crypto::signer::memory::MemorySigner`] implements
//! `AsyncSigner<F>` as `F::ready(self.try_sign_bytes_sync(..))` — the future is
//! constructed already complete. Every `.await` inside `Cgka` is therefore a
//! single `Poll::Ready` on the first poll, and the whole call graph is
//! effectively synchronous code wearing an `async` coat.
//!
//! That is what lets the rest of this crate be a *sync* state machine: no
//! executor, no `tokio`, no clock. `propsim`'s `Node::on_msg` is a synchronous
//! callback, so without this the core could not be simulated at all.

use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

/// Poll `fut` exactly once, returning its output if it was already complete.
///
/// Returns `None` if the future yielded — which, for the signers this crate
/// uses, means an invariant was broken rather than that progress is pending.
/// Callers translate `None` into
/// [`CoreError::SignerYielded`](crate::error::CoreError::SignerYielded) instead
/// of blocking, so a future runtime-backed signer fails loudly rather than
/// deadlocking a simulation.
pub fn now_or_never<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    match fut.as_mut().poll(&mut cx) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

#[cfg(test)]
mod tests {
    use super::now_or_never;

    #[test]
    fn returns_output_of_an_already_ready_future() {
        assert_eq!(now_or_never(std::future::ready(7)), Some(7));
    }

    #[test]
    fn returns_none_when_the_future_yields() {
        assert_eq!(now_or_never(std::future::pending::<u8>()), None);
    }
}
