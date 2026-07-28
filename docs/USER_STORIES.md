# User stories

# BIG PICTURE

Integrate iroh and beekem to create group-confidential workspaces?

A robust architecture for local-first, group-confidential workspaces. Iroh handles networking, NAT traversal, and P2P data replication, while BeeKEM manages dynamic group key agreement, access control, and end-to-end encryption without requiring a central server.

## Architectural Roles
To build a private workspace, responsibilities are split into two distinct layers:

### Networking & Replication (Iroh)
iroh::Endpoint: Establishes peer-to-peer QUIC connections across NATs using hole punching and relays.
iroh-gossip: Handles real-time, peer-to-peer pub/sub broadcasting for workspace updates and key tree changes.
iroh-blobs: Manages store and transfer of encrypted binary assets, large attachments, or persistent document snapshots.

### Group Confidentiality & Access Control (BeeKEM)
Dynamic Key Tree: Maintains group membership in a binary tree where leaf nodes store members' Diffie-Hellman (DH) keys and the root derives the shared workspace Epoch Key.
Continuous Group Key Agreement (CGKA): Provides Forward Secrecy (FS) and Post-Compromise Security (PCS) by allowing members to rotate keys independently.
Serverless Concurrency: Unlike standard TreeKEM (used in MLS), BeeKEM is designed to merge concurrent key rotations without needing a central coordinator to total-order operations.



## User invitation

As a workspace admin, I want to invite a new teammate so they can immediately access workspace files without creating a central cloud account.

## Diff Reconcilation

As a remote collaborator working offline on a flight, I want to edit workspace documents locally and have my changes automatically and securely merge when I reconnect.

## User removal

As a project lead, I want to remove a departing team member so they can no longer read documents, document updates or workspace changes.

## Large assets

I want to attach large (e.g. multi-gigabyte) binary assets to a workspace entry without leaking file metadata or slowing down document synchronization.