# Reporting a vulnerability

Mail **security@airdress.co**. We answer; please allow us to fix before
publishing.

## What this crate is responsible for

It builds and verifies RFC 9421 HTTP message signatures for one
profile: the covered components, the canonical form of the bytes that
get signed, and the checks a verifier performs. A defect here is a
signature that verifies when it should not, or bytes that two
implementations canonicalise differently.

Worth reporting even if it looks small:

- a covered component that is signed but not verified, or verified but
  not signed;
- any input that makes the signature base ambiguous — two distinct
  requests with one signature base is a forgery primitive;
- a verification path that accepts a missing or empty `created`, or a
  `created` arbitrarily far in the past or future;
- a comparison on secret-adjacent material that is not constant time.

## What it is not responsible for

Key custody, transport, and whether a caller is authorised once its
signature verifies. Those belong to the operator that uses it.
