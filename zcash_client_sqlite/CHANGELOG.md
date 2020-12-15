# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to Rust's notion of
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2020-10-24
### Fixed
- `transact::create_to_address` now correctly reconstructs notes from the data
  DB after Canopy activation (zcash/librustzcash#311). This is critcal to correct
  operation of spends after Canopy.
