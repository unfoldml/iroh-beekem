//! A complete workspace session between two peers, on one machine, over real QUIC.
//!
//! ```bash
//! cargo run -p iroh-beekem --example two_node
//! ```
//!
//! Alice founds a workspace, invites Bob, both edit, and Alice then revokes Bob
//! and writes again — demonstrating that revocation actually takes hold.

use std::time::Duration;

use iroh_beekem::{Node, Workspace};
use iroh_beekem_core::DocumentUuid;
use keyhive_crypto::{
    share_key::ShareSecretKey, signer::memory::MemorySigner, verifiable::Verifiable,
};
use rand::rngs::OsRng;

const DOC: DocumentUuid = DocumentUuid([1u8; 16]);

/// Poll until `check` passes or the deadline expires.
async fn settle<F, Fut>(what: &str, timeout: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        if check().await {
            println!("  ✓ {what}");
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("  ✗ timed out waiting for {what}");
    false
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `loro` and `iroh-docs` log a lot at INFO; only surface real problems.
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    println!("binding two endpoints...");
    let alice_node = Node::spawn().await?;
    let bob_node = Node::spawn().await?;

    let alice = Workspace::create(alice_node, DOC, &mut OsRng).await?;
    println!("alice founded workspace {}", alice.namespace());
    println!("  endpoint: {}", alice.endpoint_id());

    // Bob generates a leaf keypair and publishes only its public half. His
    // secret never leaves this process's Bob-side state.
    let bob_signer = MemorySigner::generate(&mut OsRng);
    let bob_secret = ShareSecretKey::generate(&mut OsRng);
    let bob_id = beekem::id::MemberId::from(bob_signer.verifying_key());

    println!("\nalice invites bob...");
    let invite = alice.invite(bob_id, bob_secret.share_key()).await?;
    println!("  invite carries {} CGKA operations", invite.log.len());

    let bob = Workspace::join(bob_node, &invite, bob_signer, bob_secret, DOC, &mut OsRng).await?;
    println!("  bob joined; group size = {}", bob.group_size().await);

    println!("\nalice writes...");
    alice.append("Hello from Alice. ").await?;
    settle("bob sees alice's edit", Duration::from_secs(30), || async {
        bob.ingest().await;
        bob.text().await.contains("Hello from Alice")
    })
    .await;

    println!("\nbob writes...");
    bob.append("And hello from Bob. ").await?;
    settle("alice sees bob's edit", Duration::from_secs(30), || async {
        alice.ingest().await;
        alice.text().await.contains("hello from Bob")
    })
    .await;

    println!("\nalice revokes bob, then writes again...");
    alice.revoke(bob_id).await?;
    alice.append("SECRET-AFTER-REVOCATION").await?;

    // Give the network every chance to deliver it; bob simply cannot derive
    // the key, so the content stays opaque to him.
    tokio::time::sleep(Duration::from_secs(3)).await;
    bob.ingest().await;

    let bob_text = bob.text().await;
    let leaked = bob_text.contains("SECRET-AFTER-REVOCATION");
    println!("  alice sees: {:?}", alice.text().await);
    println!("  bob sees:   {bob_text:?}");
    println!(
        "  {} revoked member {} read post-revocation content",
        if leaked { "✗" } else { "✓" },
        if leaked { "COULD" } else { "could not" }
    );

    alice.shutdown().await?;
    bob.shutdown().await?;

    if leaked {
        return Err("revocation failed to take hold".into());
    }
    Ok(())
}
