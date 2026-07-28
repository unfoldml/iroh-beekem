//! A complete workspace session between two peers, on one machine, over real QUIC.
//!
//! ```bash
//! cargo run -p iroh-beekem --example two_node
//! ```
//!
//! Alice founds a workspace, invites Bob, both edit, and Alice then revokes Bob
//! and writes again — demonstrating that revocation actually takes hold.

use std::time::Duration;

use iroh_beekem::{Identity, Node, Workspace};
use iroh_beekem_core::{Role, WorkspaceInfo};
use rand::rngs::OsRng;

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

    // The founder's identity is worth keeping: it determines the tree id, and
    // it is this device's leaf. Generating one in passing would leave no way to
    // come back as the same member.
    let alice_identity = Identity::generate(&mut OsRng);
    let alice = Workspace::create(
        alice_node,
        &alice_identity,
        WorkspaceInfo {
            name: "Greetings".into(),
            description: "A two-node demo workspace".into(),
        },
        &mut OsRng,
    )
    .await?;
    alice.set_display_name("Alice").await?;
    println!("alice founded workspace {:?}", alice.info().await.name);
    println!("  namespace: {}", alice.namespace());
    println!("  endpoint:  {}", alice.endpoint_id());

    // Logical paths live only in the encrypted manifest; `iroh-docs` sees a
    // blinded 32-byte key and nothing more.
    let notes = alice
        .create_file("/notes/greetings.md", "text/markdown")
        .await?;

    // Bob generates his device identity and publishes only its public leaf key.
    // The secret half never leaves his device, which is what makes an
    // intercepted invite useless for joining.
    let bob_identity = Identity::generate(&mut OsRng);
    let bob_id = bob_identity.member_id();

    println!("\nalice invites bob as an editor...");
    let invite = alice
        .add_user(bob_id, bob_identity.share_key(), Role::Editor, "Bob")
        .await?;
    println!("  invite carries {} CGKA operations", invite.log.len());

    let bob = Workspace::join(bob_node, &invite, &bob_identity, &mut OsRng).await?;
    println!("  bob joined; group size = {}", bob.group_size().await);

    println!("\nalice writes...");
    alice.append(notes, "Hello from Alice. ").await?;
    settle("bob sees alice's edit", Duration::from_secs(30), || async {
        bob.ingest().await;
        bob.read(notes).await.contains("Hello from Alice")
    })
    .await;

    println!("\nbob writes...");
    bob.append(notes, "And hello from Bob. ").await?;
    settle("alice sees bob's edit", Duration::from_secs(30), || async {
        alice.ingest().await;
        alice.read(notes).await.contains("hello from Bob")
    })
    .await;

    // Bob seeing the workspace name and the file index means the manifest was
    // encrypted, stored at its well-known blinded key, synced and decrypted.
    settle(
        "bob sees the workspace name and file index",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.info().await.name == "Greetings"
                && bob.resolve("/notes/greetings.md").await.is_some()
        },
    )
    .await;

    println!("\nalice adds a second document...");
    let todo = alice.create_file("/notes/todo.md", "text/markdown").await?;
    alice.write(todo, "1. ship 0.1").await?;
    settle(
        "bob sees both documents",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.files().await.len() == 2 && bob.read(todo).await.contains("ship 0.1")
        },
    )
    .await;

    show(&bob).await;

    // Post-compromise security: after this, bob's old leaf secret derives no
    // further group key. The group has to keep working across it.
    println!("\nbob rotates his leaf key...");
    bob.rotate().await?;
    alice
        .append(notes, "Written after Bob's rotation. ")
        .await?;
    settle(
        "bob reads across the rotation",
        Duration::from_secs(30),
        || async {
            bob.ingest().await;
            bob.read(notes).await.contains("after Bob's rotation")
        },
    )
    .await;

    let leaked = revocation_takes_hold(&alice, &bob, bob_id, notes).await?;

    alice.shutdown().await?;
    bob.shutdown().await?;

    if leaked {
        return Err("revocation failed to take hold".into());
    }
    Ok(())
}

/// Print the workspace as one peer sees it: name, files and people.
///
/// Every line here came out of the encrypted manifest, so printing it at all
/// proves the manifest round-tripped through blinded storage and back.
async fn show(ws: &Workspace) {
    println!("  workspace as bob sees it: {:?}", ws.info().await.name);
    for file in ws.files().await {
        println!("    {} ({})", file.logical_path, file.mime_type);
    }
    for user in ws.users().await {
        println!(
            "    {:?} → {:?} ({} device(s))",
            user.display_name,
            user.role,
            user.devices.len()
        );
    }
}

/// Demonstrate that revocation actually takes hold, and report whether it leaked.
///
/// Returns `true` if the revoked member could still read post-revocation
/// content, which would mean the guarantee failed.
async fn revocation_takes_hold(
    alice: &Workspace,
    bob: &Workspace,
    bob_id: beekem::id::MemberId,
    notes: iroh_beekem_core::DocumentUuid,
) -> Result<bool, Box<dyn std::error::Error>> {
    // Roles are enforced, not decorative: bob is an editor, not an admin.
    println!("\nbob (an editor) tries to revoke alice...");
    match bob.remove_device(alice.member_id().await).await {
        Err(err) => println!("  ✓ refused: {err}"),
        Ok(()) => println!("  ✗ a non-admin was allowed to revoke a member"),
    }

    println!("\nalice revokes bob, then writes again...");
    alice.remove_device(bob_id).await?;
    alice.append(notes, "SECRET-AFTER-REVOCATION").await?;

    // Give the network every chance to deliver it; bob simply cannot derive the
    // key, so the content stays opaque to him.
    tokio::time::sleep(Duration::from_secs(3)).await;
    bob.ingest().await;

    let bob_text = bob.read(notes).await;
    let leaked = bob_text.contains("SECRET-AFTER-REVOCATION");
    println!("  alice sees: {:?}", alice.read(notes).await);
    println!("  bob sees:   {bob_text:?}");
    println!(
        "  {} revoked member {} read post-revocation content",
        if leaked { "✗" } else { "✓" },
        if leaked { "COULD" } else { "could not" }
    );
    Ok(leaked)
}
