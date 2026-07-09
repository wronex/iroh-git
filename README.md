# git-iroh

This is an [Iroh](https://github.com/n0-computer/iroh) transport layer for [git](https://git-scm.com/). Push and pull directly from your friend's computer behind NAT, without open port, fixed IP-addresses, or a VPN.

## Introduction

Iroh is a P2P (direct connection) and E2E (end-to-end encrypted) communication layer that allows two computers to communicate even though both are behind NAT. Instead of IP-addresses Iroh uses the public part of an Ed25519 cryptographic key pair as the address. This is known as a NODE_ID. The key pair provides a stable, dial-able identifier that stays the same regardless of which network the computer is currently connected to. The IP-address can change.

There is an Iroh specific relay involved to facilitate NAT punch-thru and IP-address lookup while forming a connection. But these are details that mostly don't matter. The connection is end-to-end encrypted and according to Iroh's documentation, most of the time, a direct connection is formed between the two parties. The relay is only used for the initial discovery and punch-thru.

Both parties know which encryption keys to accept. The iroh-git server (`iroh-git-daemon` / `iroh-git-tray`) listens for incoming connections but only accepts connections from a list of known and allowed NODE_IDs. The dialing client has an `iroh://<ticket>/<repo_name>.git` URL that contains the server's NODE_ID and relay URL.

## Download

Download the latest release from GitHub. Download the pre-compiled binaries for Windows, or download the source and compile your own by running `cargo build --release`.

## Setup

Add `git-iroh`, `git-remote-iroh`, and `git-lfs-iroh` to your PATH. These are used by git, and you, to configure the daemon and to communicate with iroh-enabled git servers (remotes.) Access `git-iroh` through `git iroh <command>` on your command line. `git-lfs-iroh` is the Git LFS transfer agent and only needs to be on your PATH if you use LFS (see the Git LFS section below.)

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

Stop sharing an entire repository with `git iroh stop <share_id>`, using the SHARE_ID shown in `git iroh list`. This works from any directory. Pass `--this` instead of a SHARE_ID to stop sharing the repository in the current directory, or `--all` to stop sharing every repository at once.

## Git LFS

[Git LFS](https://git-lfs.com/) is also supported. The small pointer files travel in the normal git pack, while the object contents move over a separate iroh channel. LFS is off by default. The repository owner enables LFS per repository and grants each member the LFS right explicitly.

Grant a member the LFS right with `git iroh grant <node_id> --lfs` (append `--write` to also allow uploads), then turn on LFS serving for the repository with `git iroh lfs-enable`. The grant is what shares the repository; `lfs-enable` only toggles a repository you already share.

	$ git iroh grant 877c36753fcc84f71f9f804010ab4d0941d0a88ab95c1afabc09d93c6be6712c --lfs --write
	$ git iroh lfs-enable
	LFS enabled for C:\repositories\my_repo

The `--lfs` flag is additive, just like `--write`. Revoke it with `git iroh revoke <node_id> --lfs`, which removes only the LFS right and leaves clone and push access intact. Turn LFS back off for the whole repository with `git iroh lfs-disable`. `git iroh list` marks LFS-enabled repositories with `(LFS on)` and LFS-granted members with `+lfs`.

On Windows, the tray exposes the same controls: the grant dialog has an "Allow Git LFS transfer" checkbox, and each shared repository's menu has a checkable "Share Git LFS objects" item that toggles the repository's LFS switch.

On the cloning side, each clone has to be pointed at the iroh transfer agent once. Git LFS will not run a transfer agent named by a cloned repository (a safeguard against running arbitrary programs on clone), so this setting cannot be committed to the repository. Run `git iroh lfs-setup` in the clone:

	$ git iroh lfs-setup

After that, `git lfs pull`, `git lfs fetch`, and `git lfs push` transfer objects over the iroh remote as usual. The `git-lfs-iroh` binary must be on your PATH.

The `git lfs pull/fetch/push` commands are sequential. LFS transfers run as a single agent process at a time. Running several at once would each claim your client identity and collide on the relay. If you need more speed, use the iroh specific version `git iroh lfs-pull` or `git iroh lfs-push`. These commands get their concurrency by fanning out over a single connection from one process.

Run `git iroh lfs-pull` to fetch the objects referenced by HEAD that are missing locally and check them out, and `git iroh lfs-push` to upload referenced objects the daemon does not already have. Run `git iroh lfs-push` before `git push` so the receiver can resolve the pointers it is about to receive.

## Limitations

All members see all refs. There is only per-repository access control. When a node is granted read or write access they can access all branches in the git repository.

There are no size limits. The repository can grow unbounded and fill your hard drive. The same goes for LFS objects. They can grow arbitrarily large and numerous.

Access control protects the server, not the cloner. Whoever issued the ticket controls every byte of repository content you receive, so cloning a ticket means the same thing as cloning any other untrusted remote. Git's worst client-side vulnerabilities (CVE-2018-11235, CVE-2019-19604, CVE-2024-32002) are all triggered by recursive submodule clones from a hostile repository. Do not use `--recurse-submodules`, and do not run hooks or build scripts, on a ticket you do not fully trust. Keep your git client up to date.

The daemon homes on [n0 computer](https://n0.computer/)'s default relay and publishes its address record to n0's DNS service (`iroh.link`), so it can be found even when a ticket carries no relay hint. The dialing client registers nowhere: it contacts the daemon through the relay named in the ticket and only falls back to a DNS lookup if the hint is missing. No DHT is involved on either side.
