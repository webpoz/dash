Release Process
====================

* Update translations, see [translation_process.md](https://github.com/dashpay/dash/blob/master/doc/translation_process.md#synchronising-translations).

* Update manpages, see [gen-manpages.sh](https://github.com/dashpay/dash/blob/master/contrib/devtools/README.md#gen-manpagessh).
* Update release candidate version in `configure.ac` (`CLIENT_VERSION_RC`)

Before every minor and major release:

* Update [bips.md](bips.md) to account for changes since the last release.
* Update version in `configure.ac` (don't forget to set `CLIENT_VERSION_IS_RELEASE` to `true`) (don't forget to set `CLIENT_VERSION_RC` to `0`)
* Write release notes (see below)
* Update `src/chainparams.cpp` nMinimumChainWork with information from the getblockchaininfo rpc.
* Update `src/chainparams.cpp` defaultAssumeValid with information from the getblockhash rpc.
  - The selected value must not be orphaned so it may be useful to set the value two blocks back from the tip.
  - Testnet should be set some tens of thousands back from the tip due to reorgs there.
  - This update should be reviewed with a reindex-chainstate with assumevalid=0 to catch any defect
     that causes rejection of blocks in the past history.

Before every major release:

* Update hardcoded [seeds](/contrib/seeds/README.md). TODO: Give example PR for Dash
* Update [`src/chainparams.cpp`](/src/chainparams.cpp) m_assumed_blockchain_size and m_assumed_chain_state_size with the current size plus some overhead (see [this](#how-to-calculate-m_assumed_blockchain_size-and-m_assumed_chain_state_size) for information on how to calculate them).
* Update `src/chainparams.cpp` chainTxData with statistics about the transaction count and rate. Use the output of the RPC `getchaintxstats`, see
  [this pull request](https://github.com/bitcoin/bitcoin/pull/12270) for an example. Reviewers can verify the results by running `getchaintxstats <window_block_count> <window_last_block_hash>` with the `window_block_count` and `window_last_block_hash` from your output.

### First time / New builders

Install Guix using one of the installation methods detailed in
[contrib/guix/INSTALL.md](/contrib/guix/INSTALL.md).

Check out the source code in the following directory hierarchy.

	cd /path/to/your/toplevel/build
    git clone https://github.com/dashpay/guix.sigs.git
	git clone https://github.com/dashpay/dash-detached-sigs.git
	git clone https://github.com/dashpay/dash.git

### Dash Core maintainers/release engineers, suggestion for writing release notes

Write release notes. git shortlog helps a lot, for example:

    git shortlog --no-merges v(current version, e.g. 0.12.2)..v(new version, e.g. 0.12.3)

Generate list of authors:

    git log --format='- %aN' v(current version, e.g. 0.16.0)..v(new version, e.g. 0.16.1) | sort -fiu

Tag version (or release candidate) in git

    git tag -s v(new version, e.g. 0.12.3)

### Setup and perform Guix builds

Checkout the Bitcoin Core version you'd like to build:

```sh
    pushd ./dash
    export SIGNER="(your builder key, ie UdjinM6, Pasta, etc)"
    export VERSION=(new version, e.g. 0.12.3)
    git fetch
    git checkout v${VERSION}
    popd
```

Ensure your guix.sigs are up-to-date if you wish to `guix-verify` your builds
against other `guix-attest` signatures.

```sh
git -C ./guix.sigs pull
```

### Create the macOS SDK tarball: (first time, or when SDK version changes)

Create the macOS SDK tarball, see the [macdeploy
instructions](/contrib/macdeploy/README.md#deterministic-macos-dmg-notes) for
details.

### Build and attest to build outputs:

Follow the relevant Guix README.md sections:
- [Performing a build](/contrib/guix/README.md#performing-a-build)
- [Attesting to build outputs](/contrib/guix/README.md#attesting-to-build-outputs)

### Verify other builders' signatures to your own. (Optional)

Add other builders keys to your gpg keyring, and/or refresh keys: See `../bitcoin/contrib/builder-keys/README.md`.

Follow the relevant Guix README.md sections:
- [Verifying build output attestations](/contrib/guix/README.md#verifying-build-output-attestations)

Build output expected:

  1. source tarball (`dash-${VERSION}.tar.gz`)
  2. linux 32-bit and 64-bit dist tarballs (`dash-${VERSION}-linux[32|64].tar.gz`)
  3. windows 32-bit and 64-bit unsigned installers and dist zips (`dash-${VERSION}-win[32|64]-setup-unsigned.exe`, `dash-${VERSION}-win[32|64].zip`)
  4. macOS unsigned installer and dist tarball (`dash-${VERSION}-osx-unsigned.dmg`, `dash-${VERSION}-osx64.tar.gz`)
  5. Gitian signatures (in `gitian.sigs/${VERSION}-<linux|{win,osx}-unsigned>/(your Gitian key)/`)

### Next steps:

Commit your signature to guix.sigs:

    pushd gitian.sigs
    git add ${VERSION}-linux/"${SIGNER}"
    git add ${VERSION}-win-unsigned/"${SIGNER}"
    git add ${VERSION}-osx-unsigned/"${SIGNER}"
    git commit -a
    git push  # Assuming you can push to the gitian.sigs tree
    popd

Codesigner only: Create Windows/macOS detached signatures:
- Only one person handles codesigning. Everyone else should skip to the next step.
- Only once the Windows/macOS builds each have 3 matching signatures may they be signed with their respective release keys.

Codesigner only: Sign the macOS binary:

    transfer dashcore-osx-unsigned.tar.gz to macOS for signing
    tar xf dashcore-osx-unsigned.tar.gz
    ./detached-sig-create.sh -s "Key ID" -o runtime
    Enter the keychain password and authorize the signature
    Move signature-osx.tar.gz back to the guix-build host

Codesigner only: Sign the windows binaries:

    tar xf dashcore-win-unsigned.tar.gz
    ./detached-sig-create.sh -key /path/to/codesign.key
    Enter the passphrase for the key when prompted
    signature-win.tar.gz will be created

Codesigner only: Commit the detached codesign payloads:

    cd ~/dashcore-detached-sigs
    checkout the appropriate branch for this release series
    rm -rf *
    tar xf signature-osx.tar.gz
    tar xf signature-win.tar.gz
    git add -A
    git commit -m "point to ${VERSION}"
    git tag -s v${VERSION} HEAD
    git push the current branch and new tag

Non-codesigners: wait for Windows/macOS detached signatures:

- Once the Windows/macOS builds each have 3 matching signatures, they will be signed with their respective release keys.
- Detached signatures will then be committed to the [dash-detached-sigs](https://github.com/dashpay/dash-detached-sigs) repository, which can be combined with the unsigned apps to create signed binaries.

Create (and optionally verify) the codesigned outputs:

    pushd ./gitian-builder
    ./bin/gbuild -i --commit signature=v${VERSION} ../dash/contrib/gitian-descriptors/gitian-osx-signer.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-osx-signed --destination ../gitian.sigs/ ../dash/contrib/gitian-descriptors/gitian-osx-signer.yml
    ./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-osx-signed ../dash/contrib/gitian-descriptors/gitian-osx-signer.yml
    mv build/out/dash-osx-signed.dmg ../dash-${VERSION}-osx.dmg
    popd

Create (and optionally verify) the signed Windows binaries:

    pushd ./gitian-builder
    ./bin/gbuild -i --commit signature=v${VERSION} ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-win-signed --destination ../gitian.sigs/ ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
    ./bin/gverify -v -d ../gitian.sigs/ -r ${VERSION}-win-signed ../dash/contrib/gitian-descriptors/gitian-win-signer.yml
    mv build/out/dash-*win64-setup.exe ../dash-${VERSION}-win64-setup.exe
    popd

Commit your signature for the signed macOS/Windows binaries:

```sh
pushd ./guix.sigs
git add "${VERSION}/${SIGNER}"/all.SHA256SUMS{,.asc}
git commit -m "Add ${SIGNER} ${VERSION} signed binaries signatures"
git push  # Assuming you can push to the guix.sigs tree
popd
```

### After 3 or more people have guix-built and their results match:

Combine `all.SHA256SUMS` and `all.SHA256SUMS.asc` into a clear-signed
`SHA256SUMS.asc` message:

```sh
echo -e "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n$(cat all.SHA256SUMS)\n$(cat filename.txt.asc)" > SHA256SUMS.asc
```

Here's an equivalent, more readable command if you're confident that you won't
mess up whitespaces when copy-pasting:

```bash
cat << EOF > SHA256SUMS.asc
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

$(cat all.SHA256SUMS)
$(cat all.SHA256SUMS.asc)
EOF
```

The list of files should be:
```
dash-${VERSION}-aarch64-linux-gnu.tar.gz
dash-${VERSION}-riscv64-linux-gnu.tar.gz
dash-${VERSION}-x86_64-linux-gnu.tar.gz
dash-${VERSION}-osx64.tar.gz
dash-${VERSION}-osx.dmg
dash-${VERSION}.tar.gz
dash-${VERSION}-win64-setup.exe
dash-${VERSION}-win64.zip
```
The `*-debug*` files generated by the Gitian build contain debug symbols
for troubleshooting by developers. It is assumed that anyone that is interested
in debugging can run Gitian to generate the files for themselves. To avoid
end-user confusion about which file to pick, as well as save storage
space *do not upload these to the dash.org server*.

       The `*-debug*` files generated by the guix build contain debug symbols
       for troubleshooting by developers. It is assumed that anyone that is
       interested in debugging can run guix to generate the files for
       themselves. To avoid end-user confusion about which file to pick, as well
       as save storage space *do not upload these to the bitcoincore.org server,
       nor put them in the torrent*.

- Upload zips and installers, as well as `SHA256SUMS.asc` from last step, to the dash.org server

- Update dash.org

- Announce the release:

  - Release on Dash forum: https://www.dash.org/forum/topic/official-announcements.54/

  - Optionally Discord, twitter, reddit /r/Dashpay, ... but this will usually sort out itself

  - Notify flare so that he can start building [the PPAs](https://launchpad.net/~dash.org/+archive/ubuntu/dash)

  - Archive release notes for the new version to `doc/release-notes/` (branch `master` and branch of the release)

  - Create a [new GitHub release](https://github.com/dashpay/dash/releases/new) with a link to the archived release notes.

  - Celebrate

### Additional information

#### How to calculate `m_assumed_blockchain_size` and `m_assumed_chain_state_size`

Both variables are used as a guideline for how much space the user needs on their drive in total, not just strictly for the blockchain.
Note that all values should be taken from a **fully synced** node and have an overhead of 5-10% added on top of its base value.

To calculate `m_assumed_blockchain_size`:
- For `mainnet` -> Take the size of the Dash Core data directory, excluding `/regtest` and `/testnet3` directories.
- For `testnet` -> Take the size of the `/testnet3` directory.


To calculate `m_assumed_chain_state_size`:
- For `mainnet` -> Take the size of the `/chainstate` directory.
- For `testnet` -> Take the size of the `/testnet3/chainstate` directory.

Notes:
- When taking the size for `m_assumed_blockchain_size`, there's no need to exclude the `/chainstate` directory since it's a guideline value and an overhead will be added anyway.
- The expected overhead for growth may change over time, so it may not be the same value as last release; pay attention to that when changing the variables.
