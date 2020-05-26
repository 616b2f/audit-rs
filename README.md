# audit-rs = Dependency Vulnerability Scanner

> :warning: This is work in progress. I write it mostly for learning Rust.:warning:

#### Dependencies

- cargo >= 1.43.0
- rustc >= 1.43

Platform Support:
- Windows (not tested)
- MacOS (not tested)
- Linux (Testet with Ubuntu 20.04)

## How to build

```sh
$ cargo build --release
```

The executable is named `audit`, file extension can vary depending on your platform. You will find the executable in `target/release/` folder.

## How to use

```sh
$ audit --project "test" --scan "./test-proj-files/dotnet-example2/project.assets.json"
```
currently only `project.assets.json` is supported.