# audit-rs = Dependency Vulnerability Scanner

> :warning: This is work in progress. I write it mostly for learning Rust.:warning:

#### Dependencies

- cargo >= 1.43.0
- rustc >= 1.43

Platform Support:
- Windows (not tested)
- MacOS (not tested)
- Linux (Testet with Ubuntu 20.04)

Included Analysers:
- dotnet analyser
- npm analyser

## How to build

```sh
$ cargo build --release
```

The executable is named `audit`, file extension can vary depending on your platform. You will find the executable in `target/release/` folder.

## How to use

You need to build your projects first, this is needed because many tools generate files that represent the dependency graph of your project. You can use glob pattern to specify which files hould be scanned.

For example to scan our test project files use this:

```sh
$ audit --project "test" --scan "./test-proj-files/**/*"
```
Currently we look for `project.assets.json` and `project-lock.json` files to scan.