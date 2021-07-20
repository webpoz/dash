<<<<<<< HEAD:contrib/gitian-keys/README.md
PGP keys
========

This folder contains the public keys of developers and active contributors.

The keys are mainly used to sign git commits or the build results of Gitian
builds.
=======
## PGP keys of builders and Developers

The file `keys.txt` contains fingerprints of the public keys of builders and
active developers.

The associated keys are mainly used to sign git commits or the build results
of Guix builds.
>>>>>>> e7441a6a45 (Merge bitcoin/bitcoin#21711: guix: Add full installation and usage documentation):contrib/builder-keys/README.md

You can import the keys into gpg as follows. Also, make sure to fetch the
latest version from the key server to see if any key was revoked in the
meantime.

```sh
gpg --import ./*.pgp
gpg --refresh-keys
```
<<<<<<< HEAD:contrib/gitian-keys/README.md
=======

To fetch keys of builders and active developers, feed the list of fingerprints
of the primary keys into gpg:

```sh
while read fingerprint keyholder_name; do gpg --keyserver hkp://subset.pool.sks-keyservers.net --recv-keys ${fingerprint}; done < ./keys.txt
```

Add your key to the list if you provided Guix attestations for two major or
minor releases of Bitcoin Core.
>>>>>>> e7441a6a45 (Merge bitcoin/bitcoin#21711: guix: Add full installation and usage documentation):contrib/builder-keys/README.md
