# git-iroh

This is an [Iroh](https://github.com/n0-computer/iroh) transport layer for [git](https://git-scm.com/). Push and pull directly from your friend's computer behind NAT, without open port, fixed IP-addresses, or a VPN.

## Introduction

Iroh is a P2P (direct connection) and E2E (end-to-end encrypted) communication layer that allows two computers to communicate even though both are behind NAT. Instead of IP-addresses Iroh uses the public part of an Ed25519 cryptographic key pair as the address. This is known as a NODE_ID. The key pair provides a stable, dial-able identifier that stays the same regardless of which network the computer is currently connected to. The IP-address can change.

There is an Iroh specific relay involved to facilitate NAT punch-thru and IP-address lookup while forming a connection. But these are details that mostly don't matter. The connection is end-to-end encrypted and according to Iroh's documentation, most of the time, a direct connection is formed between the two parties. The relay is only used for the initial discovery and punch-thru.

Both parties know which encryption keys to accept. The iroh-git server (`iroh-git-daemon` / `iroh-git-tray`) listens for incoming connections but only accepts connections from a list of known and allowed NODE_IDs. The dialing client has an `iroh://<ticket>/<repo_name>.git` URL that contains the server's NODE_ID and relay URL.

## Download

Download the latest release from GitHub. Download the pre-compiled binaries for Windows, or download the source and compile your own by running `cargo build --release`.

## Setup

Add `git-iroh` and `git-remote-iroh` to your PATH. These are used by git, and you, to configure the daemon and to communicate with iroh-enabled git servers (remotes.) Access `git-iroh` through `git iroh <command>` on your command line.

`iroh-git-daemon` is used to serve git repositories on your computer. This is the long-running server that listens for incoming connections and deals with access control. For Windows users, there is an alternative daemon called `iroh-git-tray`; it provides a notification icon and rudimentary UI.

Configuration values are stored on disk:

* Windows: `%APPDATA%\iroh-git`
* Linux: `$XDG_CONFIG_HOME/iroh-git` or `~/.config/iroh-git`
* macOS: `~/Library/Application Support/iroh-git`

## Cloning a repository

Run `git iroh show-id` to print your computer's NODE_ID. 

	$ git iroh show-id
	877c36753fcc84f71f9f804010ab4d0941d0a88ab95c1afabc09d93c6be6712c

Hand your NODE_ID to the git server operator. They then grant access to one or more repositories by running `git iroh grant <node_id> [--write] [--name <name>]` in one or more repositories. This returns a git cloneable URL on the format `iroh://<ticket>/<repo_name>.git`.

	$ cd C:\repositories\my_repo
	$ git iroh grant 877c36753fcc84f71f9f804010ab4d0941d0a88ab95c1afabc09d93c6be6712c --write --name erik
	granted read-write access to C:\repositories\my_repo
	iroh://tfzuupmqj2mutd66lykmt7u4xstmidaht6u5zbmy22vdwka7cikqci3ior2ha4z2f4xwk5ldgewtcltsmvwgc6jonyyc42lsn5uc43djnzvs4l5n23aeyh64bhxkjgwynbyr5xca/my_repo.git

Then you run `git clone <url>` to clone the repo:

	git clone iroh://tfzuupmqj2mutd66lykmt7u4xstmidaht6u5zbmy22vdwka7cikqci3ior2ha4z2f4xwk5ldgewtcltsmvwgc6jonyyc42lsn5uc43djnzvs4l5n23aeyh64bhxkjgwynbyr5xca/my_repo.git

Now you can push and pull using git as you normally would.

Keep in mind that git does not like when you push to a checked out branch. This can be configured and git will show a nice error message if you try. It is recommended to use bare repositories as your remote though. Or, you will need to figure out how to only push to non-checked out branches.

## Access control

Use `git iroh list` to see shared repositories:

	$ git iroh list
	C:\repositories\my_repo  [vxlmata73qe65je23buhchw4ia]
    	rw  erik  (877c36753fcc84f71f9f804010ab4d0941d0a88ab95c1afabc09d93c6be6712c)

Use `git iroh grant <node_id> [--write] [--name <name>]` to grant access to the repository in the current directory. The `--write` flag enables write (push) access; default is read-only (pull) access. The `--name` flag is used to add a nickname to the NODE_ID; it shows up in `git iroh list`.

Revoke a member's access with `git iroh revoke <node_id>`. This removes the member from the repository in the current directory. Append `--write` to revoke their write access only, leaving read access intact. Append `--all` to remove the member from every repository you share, not just the one in the current directory.

Stop sharing an entire repository with `git iroh stop <share_id>`, using the SHARE_ID shown in `git iroh list`. This works from any directory. Pass `--all` instead of a SHARE_ID to stop sharing every repository at once.

## Limitations

All members see all refs. There is only per-repository access control. When a node is granted read or write access they can access all branches in the git repository.

No LFS support at this time.

The daemon registers with [n0 computer](https://n0.computer/)'s default relay and discovery service.
