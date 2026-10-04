# airdress-httpsig

The [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html)
request-signing profile airdress operators sign with — one
implementation, so every signer agrees on the bytes.

```toml
[dependencies]
airdress-httpsig = { git = "https://github.com/airdress-co/airdress-httpsig", tag = "v0.2.0" }
```

## Why it is its own crate

It used to live in `airdress-operator/crates/airdress-httpsig`, and
`airdress-cli` pulled it by git tag from that private repository. When
the CLI became public that one dependency was what stopped a public
checkout from building: a private source, and `LicenseRef-Proprietary`
inherited from the operator's workspace.

Vendoring the 233 lines into the CLI was cheaper and was rejected. The
pinned tag existed precisely to keep one copy of this logic, and a
vendored second copy is how two signers drift until a signature
verifies in one place and not the other.

So it moved here with its history, relicensed Apache-2.0 by the
copyright holder, and both the CLI and the operator depend on this one
revision.

## What it does, and what it deliberately does not

It covers one profile rather than all of RFC 9421: the components we
sign, the canonical form of the signature base, and the verification a
peer performs. That narrowness is the feature — two implementations of
"all of RFC 9421" can both be correct and still disagree on a request.

It does not hold keys, choose a transport, or decide whether a verified
caller is allowed to do anything. Those belong to the operator.

## The one pin that matters

`httpsig-hyper` is pinned exactly (`=0.0.26`). It is pre-1.0, so a
patch bump can change the signature base, and the pin must match the
one wherever else this is compiled in — two versions in one binary
means two canonical forms and signatures that verify inconsistently.
Bumping it is a reviewed change, not a `cargo update`.

## Security

See [SECURITY.md](./SECURITY.md). Mail security@airdress.co.

## Licence

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
