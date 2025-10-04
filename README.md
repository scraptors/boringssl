# boringssl patches

This contains a patched version of google's boringssl based based [cloudflare's patches](https://github.com/cloudflare/boring).

The root commit is `44b3df6f03d85c901767250329c571db405122d5`

> [!CAUTION]
> The root branch is base-patches. This does not compile, at all as it is purely meant for generating diffs to apply to other branches.

## Steps to produce patch

1. Create new patched branch based on main (e.g. when cloudflare updates their branch await from `44b3df6f03d85c901767250329c571db405122d5`)
2. Switch back to main and do `git branch -f test $NEW_BASE_HASH`
3. Apply prescribed (cloudflare) patches to branch.
4. Merge or rebase `base-patches` into this new branch (if possible)
5. Add additional changes to shared files.


## Overlapping changes

These files need to be changed to maintain an up to date patch

- ssl_key_share.cc add MLKEM1024 and ffdhe support (most effort)
- extensons.cc add KYBER support from cloudflare https://github.com/cloudflare/boring/blob/75ef5232300a7d005578003c2dfc4d2b38cb7b8a/boring-sys/patches/boring-pq.patch#L3922C1-L3925C37
- ssl_lib.cc from cloudflare https://github.com/cloudflare/boring/blob/75ef5232300a7d005578003c2dfc4d2b38cb7b8a/boring-sys/patches/boring-pq.patch#L4560C1-L4560C112
- include/openssl/nid.h add ffdhe support from patches
- include/openssl/ssl.h export consts and expose some API from patches
