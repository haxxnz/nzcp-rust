# NZCP Rust &emsp; [![Latest Version]][crates.io] [![Documentation]][docs.rs]

[latest version]: https://img.shields.io/crates/v/nzcp.svg
[crates.io]: https://crates.io/crates/nzcp
[documentation]: https://img.shields.io/docsrs/nzcp
[docs.rs]: https://docs.rs/nzcp/1.0.1/nzcp/

An implementation of [NZ COVID Pass](https://github.com/minhealthnz/nzcovidpass-spec) verification, New Zealand's proof of COVID-19 vaccination solution, written in Rust 🦀

We also have a [JavaScript implementation](https://github.com/vaxxnz/nzcp-js/) available.

## Usage

Usage is very straight forward, simply call `verify_pass_uri` with the scanned QR Code URI. If the given pass is valid the function will return `Ok` with the pass details, otherwise it will return `Err` with details of the verification issue.

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
nzcp = "1.0.1"
```

```rust
use nzcp::{verify_pass_uri, PublicCovidPass};

let barcode = "NZCP:/1/2KCEVIQEIVVWK6JNGEASNICZAEP2KALYDZSGSZB2O5SWEOTOPJRXALTDN53GSZBRHEXGQZLBNR2GQLTOPICRUYMBTIFAIGTUKBAAUYTWMOSGQQDDN5XHIZLYOSBHQJTIOR2HA4Z2F4XXO53XFZ3TGLTPOJTS6MRQGE4C6Y3SMVSGK3TUNFQWY4ZPOYYXQKTIOR2HA4Z2F4XW46TDOAXGG33WNFSDCOJONBSWC3DUNAXG46RPMNXW45DFPB2HGL3WGFTXMZLSONUW63TFGEXDALRQMR2HS4DFQJ2FMZLSNFTGSYLCNRSUG4TFMRSW45DJMFWG6UDVMJWGSY2DN53GSZCQMFZXG4LDOJSWIZLOORUWC3CTOVRGUZLDOSRWSZ3JOZSW4TTBNVSWISTBMNVWUZTBNVUWY6KOMFWWKZ2TOBQXE4TPO5RWI33CNIYTSNRQFUYDILJRGYDVAYFE6VGU4MCDGK7DHLLYWHVPUS2YIDJOA6Y524TD3AZRM263WTY2BE4DPKIF27WKF3UDNNVSVWRDYIYVJ65IRJJJ6Z25M2DO4YZLBHWFQGVQR5ZLIWEQJOZTS3IQ7JTNCFDX";
let pass: PublicCovidPass = verify_pass_uri(barcode).await?;
```

### Pass Types

The library is written in a manner which allows easy addition to the types of passes that can be verified, but to date only the [My Vaccine Pass](https://github.com/minhealthnz/nzcovidpass-spec#my-vaccine-pass) spec has been published.

| Pass Name                                                                          | Struct            |
| ---------------------------------------------------------------------------------- | ----------------- |
| [My Vaccine Pass](https://github.com/minhealthnz/nzcovidpass-spec#my-vaccine-pass) | `PublicCovidPass` |

## Usage Outside of Rust

There are plans to provide cross platform libraries using this implementation for other languages, such as web browser WASM and React Native. If you'd like to create your own please do!

## Support

See something that can be improved? [Report an Issue](https://github.com/vaxxnz/nzcp-rust/issues) or contact us to [report a security concern](mailto:info@vaxx.nz).

Want to help us build a better library? We welcome contributions via [pull requests](https://github.com/vaxxnz/nzcp-rust/pulls) and welcome you to our wider [Vaxx.nz](https://vaxx.nz) community on Discord: [Join our Discord community](https://discord.gg/sJWmNy7wnM).
