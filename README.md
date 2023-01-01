# Timelock Program Authority

This program allows for the delayed upgrade of Solana smart contracts.

When a deployment is delayed, the verified source code of the upgrade can be transparently presented to the users who now have the ability to decide whether to continue interacting with said program.

### Testing

To run the tests:

```
cd program
cargo test-sbf --sbf-out-dir tests/deps
```
