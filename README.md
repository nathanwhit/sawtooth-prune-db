# sawtooth-prune-db

A CLI tool to perform offline pruning of the state database for Hyperledger Sawtooth.
Only the currently active chain is kept, which can reduce the file size of the database dramatically.
A new database is created rather than pruning in-place for performance and reliability, as a failed operation
will not corrupt the original database.

## Usage

Requires an up-to-date Rust toolchain, as well as a C/C++ compiler, cmake, and pkg-config.

1. Clone repository
```
git clone https://github.com/nathanwhit/sawtooth-prune-db.git
```
2. Build project
```
cargo build --release
```

3. Run binary
```
./target/Release/sawtooth-prune-db -v <Path to sawtooth data directory> <Output DB path>
```