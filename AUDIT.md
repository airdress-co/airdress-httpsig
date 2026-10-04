# What was checked before this repository was made public

Done 2026-10-04, when the crate was extracted from airdress-operator.
The same three questions airdress-cli's audit asks, because the answer
"it is only 233 lines" is not one of them.

## 1. Does anything here name our estate?

Checked the whole history, not the working tree — publishing a
repository publishes its history, and this one carries 54 commits from
inside a private repo.

Searched every blob for internal hostnames, our Tailscale range, the
ZITADEL tenant, operator FQDNs, bucket names and service-account
addresses. **Nothing found.** The crate is pure protocol: it takes a
request and a key and returns a signature, so it never had a reason to
name a host.

## 2. Is there a secret in it?

`gitleaks` over the full history: clean. By construction the test
vectors generate their keys in-process rather than embedding any, so
there was no key material to leak.

## 3. Can it build with no credential?

Yes, and that is the point of the move. Every dependency is public, so
`cargo test` works in a fresh clone with no token and no network access
to anything of ours. Verified on a workstation outside the workspace:
two tests pass.

## What the extraction changed, and why each

| Was | Is | Why |
| --- | --- | --- |
| `license.workspace = true` → `LicenseRef-Proprietary` | `Apache-2.0` | relicensed by the copyright holder; the proprietary marker was inherited, never deliberate for this crate |
| `publish.workspace = true` → `false` | omitted | it is publishable now |
| `edition`/`rust-version` from the workspace | `2024` / `1.92` | the same values, inlined, since there is no workspace to inherit from |
| `base64`, `rand`, `sha2`, `thiserror`, `tokio` from the workspace | explicit versions | identical versions, inlined |
| version `0.1.112` | `0.2.0` | that number tracked the operator's release train and means nothing here; starting at `0.2.0` keeps it clearly ahead of the numbers that existed inside the operator |

`httpsig-hyper = "=0.0.26"` is unchanged and must stay exact. It is
pre-1.0, so a patch bump can move the signature base, and this pin has
to match the one wherever else it is compiled in.

## What this audit does not claim

That the profile is correct. It says nothing was leaked and the thing
builds in the open. Whether the covered components are the right ones
is a review question, and `SECURITY.md` says what a defect would look
like.
