# Autel Firmware Parser

A Rust CLI tool for parsing and extracting files from Autel firmware containers.

## Usage

```
firmparse <input_file> [output_dir]
```

Recursively extracts embedded files (ZIP, JSON, etc.) from Autel's proprietary container format.

## Build

```
cargo build --release
```
