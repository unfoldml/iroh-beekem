//! Rate limiting for actions a peer can ask this node to repeat.
//!
//! # Why a clock-free crate holds a rate limiter
//!
//! [`Cooldown::claim`] is *given* an instant; it never reads one. That is the
//! same discipline as [`WorkspaceState::handle`], which takes `now` as a
//! parameter, and it is what lets the policy be checked without waiting on wall
//! time. Nothing here calls `Instant::now`, so the rule that this crate performs
//! no I/O is untouched.
//!
//! It lives here because both backends need it and both had written it. The
//! `iroh-beekem` facade had this type; the simulator open-coded the same policy
//! over a map and, having done so, never grew the *answering* half of it at all.
//! A limiter written twice is a limiter that disagrees with itself.
//!
//! # What stays with the caller
//!
//! The **windows**. The facade suppresses a repeated repair for two seconds of
//! wall clock; the simulator suppresses one for five hundred milliseconds of
//! virtual time. That difference is correct, and a shared constant would force
//! one of them to be wrong.
//!
//! [`WorkspaceState::handle`]: crate::state::WorkspaceState::handle

use std::{collections::HashMap, hash::Hash, time::Duration};

/// An instant a [`Cooldown`] can measure a window against.
///
/// Two implementations, and the pair is the point: the facade limits against
/// `std::time::Instant`, and the simulator against a `Duration` since the start
/// of a virtual run. A limiter generic over neither could not be shared, and one
/// generic over a trait the harness cannot implement would be shared in name
/// only.
pub trait Deadline: Copy {
    /// How much time has passed from `earlier` to `self`.
    ///
    /// Saturating rather than panicking: a caller handing in a non-monotonic
    /// pair is asking a question whose honest answer is "no time", and a rate
    /// limiter is the wrong place to take a node down.
    fn since(self, earlier: Self) -> Duration;
}

impl Deadline for std::time::Instant {
    fn since(self, earlier: Self) -> Duration {
        self.saturating_duration_since(earlier)
    }
}

impl Deadline for Duration {
    fn since(self, earlier: Self) -> Duration {
        self.saturating_sub(earlier)
    }
}

/// Rate limiter keyed on whatever distinguishes one occasion from the next.
///
/// Generic in the key because its users disagree about what "the same event"
/// means, and each disagreement is deliberate: neighbour-up repair is per peer;
/// an *outgoing* repair request is per `(target, epoch)`, so a peer that becomes
/// stuck on a new epoch is not silenced by the window it opened for the old one;
/// and *answering* a repair request is per requesting member, because there the
/// point is to limit the requester rather than the request.
#[derive(Debug, Clone)]
pub struct Cooldown<K, I = std::time::Instant> {
    seen: HashMap<K, I>,
    window: Duration,
}

/// A limiter that suppresses nothing.
///
/// Not derived, because a derive would demand `K: Default` for no reason and
/// would say nothing about what the value *means*. A zero window is a limiter
/// that is switched **off**: every claim is admitted. That is the honest default
/// for a harness that builds its nodes through [`Default`] and sets the real
/// window when it starts them, and it errs in the direction that matters — a
/// limiter nobody configured passes traffic rather than silently dropping it.
impl<K, I> Default for Cooldown<K, I> {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
            window: Duration::ZERO,
        }
    }
}

impl<K: Hash + Eq, I: Deadline> Cooldown<K, I> {
    /// A limiter that suppresses a repeated key for `window`.
    ///
    /// A `window` of zero suppresses nothing, which is a supported setting
    /// rather than a degenerate one: it says "this limit exists and is currently
    /// off", which is a thing a reader can see and a missing limiter is not.
    #[must_use]
    pub fn new(window: Duration) -> Self {
        Self {
            seen: HashMap::new(),
            window,
        }
    }

    /// Whether `key` may trigger its action now, recording it if so.
    ///
    /// Expired entries are pruned on the way through, so the map stays
    /// proportional to the keys seen in one window rather than to every key
    /// ever seen. Without that, a map keyed by peer id would simply move the
    /// exhaustion vector this exists to close from CPU to memory.
    pub fn claim(&mut self, key: K, now: I) -> bool {
        // An entry older than the cooldown says nothing its absence does not.
        let window = self.window;
        self.seen.retain(|_, at| now.since(*at) < window);
        match self.seen.get(&key) {
            Some(at) if now.since(*at) < window => false,
            _ => {
                self.seen.insert(key, now);
                true
            }
        }
    }

    /// How many keys are currently being tracked.
    ///
    /// Only the pruning property needs this; the policy itself never asks.
    #[must_use]
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use proptest::prelude::*;

    use super::Cooldown;

    /// Stands in for the facade's `NEIGHBOR_COOLDOWN`. The value does not matter
    /// to the policy; what matters is that the same one is used throughout a
    /// test, since the limit is a rate rather than a ban.
    const WINDOW: Duration = Duration::from_secs(10);

    #[test]
    fn a_first_arrival_is_always_allowed() {
        let mut cooldown: Cooldown<u8> = Cooldown::new(WINDOW);
        assert!(
            cooldown.claim(1, Instant::now()),
            "a peer that has never been seen must be able to repair"
        );
    }

    #[test]
    fn a_repeat_arrival_within_the_window_is_refused() {
        let mut cooldown: Cooldown<u8> = Cooldown::new(WINDOW);
        let start = Instant::now();

        assert!(cooldown.claim(1, start));
        assert!(
            !cooldown.claim(1, start + WINDOW / 2),
            "a peer reconnecting inside the window must not trigger a second repair"
        );
    }

    #[test]
    fn the_same_peer_is_allowed_again_once_the_window_passes() {
        let mut cooldown: Cooldown<u8> = Cooldown::new(WINDOW);
        let start = Instant::now();

        assert!(cooldown.claim(1, start));
        assert!(
            cooldown.claim(1, start + WINDOW),
            "the limit is a rate, not a ban: a genuine later reconnect must repair"
        );
    }

    #[test]
    fn one_peers_cooldown_does_not_suppress_another() {
        let mut cooldown: Cooldown<u8> = Cooldown::new(WINDOW);
        let start = Instant::now();

        assert!(cooldown.claim(1, start));
        assert!(
            cooldown.claim(2, start),
            "the budget is per peer; one noisy peer must not starve a quiet one"
        );
    }

    #[test]
    fn expired_entries_are_pruned_so_the_map_cannot_grow_without_bound() {
        let mut cooldown: Cooldown<u8> = Cooldown::new(WINDOW);
        let start = Instant::now();

        for peer in 0..32u8 {
            cooldown.claim(peer, start);
        }
        assert_eq!(
            cooldown.tracked(),
            32,
            "every distinct peer inside one window must be tracked, or the \
             limiter would suppress nothing"
        );

        cooldown.claim(200, start + WINDOW * 2);
        assert_eq!(
            cooldown.tracked(),
            1,
            "entries older than the window carry no information, so leaving them \
             would move the exhaustion vector from CPU to memory"
        );
    }

    /// The simulator measures against virtual time, which is a `Duration` since
    /// the start of the run rather than an `Instant`. The same policy must hold
    /// there, or the harness would be limiting on a different rule from
    /// production while appearing to share the code.
    #[test]
    fn the_policy_is_the_same_against_virtual_time() {
        let mut cooldown: Cooldown<u8, Duration> = Cooldown::new(Duration::from_millis(500));
        let start = Duration::from_millis(900);

        assert!(cooldown.claim(1, start));
        assert!(
            !cooldown.claim(1, start + Duration::from_millis(200)),
            "a virtual-time limiter must suppress inside its window exactly as a \
             wall-clock one does"
        );
        assert!(
            cooldown.claim(1, start + Duration::from_millis(500)),
            "and must release at the window's edge, or a simulated repair would \
             be silenced forever"
        );
    }

    proptest! {
        /// Given any sequence of claims for one key, when each is offered at a
        /// generated instant, we expect no two admitted claims to fall inside
        /// one window of each other. This is the whole guarantee: the limiter's
        /// users spend a group-wide re-key or a full log broadcast per admitted
        /// claim, so two inside a window is the cost the limit exists to refuse.
        #[test]
        fn a_key_is_never_admitted_twice_inside_one_window(
            window_ms in 1u64..5_000,
            gaps in proptest::collection::vec(0u64..10_000, 1..40),
        ) {
            let window = Duration::from_millis(window_ms);
            let mut cooldown: Cooldown<u8, Duration> = Cooldown::new(window);

            let mut now = Duration::ZERO;
            let mut last_admitted: Option<Duration> = None;
            for gap in gaps {
                now += Duration::from_millis(gap);
                if cooldown.claim(0, now) {
                    if let Some(previous) = last_admitted {
                        prop_assert!(
                            now.saturating_sub(previous) >= window,
                            "two claims for one key were admitted {:?} apart, \
                             inside a {window:?} window",
                            now.saturating_sub(previous)
                        );
                    } else {
                        // The first admitted claim has nothing to be too close to.
                    }
                    last_admitted = Some(now);
                } else {
                    // Suppressed, which is the other half of the policy and is
                    // covered by the release cases above.
                }
            }
        }
    }
}
