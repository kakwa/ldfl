# LDFL

[![Doxygen](https://github.com/kakwa/ldfl/actions/workflows/doxygen.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/doxygen.yml)
[![Memleak Check](https://github.com/kakwa/ldfl/actions/workflows/valgrind.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/valgrind.yml)
[![Unit Tests & Coverage](https://github.com/kakwa/ldfl/actions/workflows/coverage.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/kakwa/ldfl/graph/badge.svg?token=08AAHC625O)](https://codecov.io/gh/kakwa/ldfl)

## Presentation

LDFL (LD File Liar) is a powerful `LD_PRELOAD` library that intercepts and modify `libc` file system operations. It allows you to:

- **Log Filesystem Interactions**: File & Directory manipulation can be logged to syslog or stderr
- **Remap File Paths**: Redirect file access to different locations
- **Control File Access**: Restrict or allow access to specific files/directories
- **Modify File Permissions**: Change ownership and permissions on-the-fly
- **Memory-based Files**: Serve files directly from memory
- **Static Content**: Serve predefined static content
- **Executable Redirection**: Redirect executable paths

This tool can be used on existing binaries or can be included with a static configuration header inside your projects.

## Dependencies

The following dependencies are required to build ldfl:

- CMake (version 3.12 or higher)
- PCRE2 library
- Jansson library
- CUnit (optional, for tests)
- Doxygen (optional, for documentation)

On Ubuntu/Debian, you can install these dependencies with:
```bash
sudo apt update
sudo apt install -y cmake libpcre2-dev libjansson-dev libcunit1-dev doxygen
```

## Documentation

API documentation is available in the `docs/html` directory after building with `-DBUILD_DOC=ON`. You can also view the latest documentation online at [GitHub Pages](https://kakwa.github.io/ldfl/).

## Development

1. Clone the repository:
```bash
git clone https://github.com/kakwa/ldfl.git
cd ldfl
```

2. Create a build directory and configure CMake:
```bash
cmake .
```

3. Build the project:
```bash
make
```

Optional build options:
- `-DBUILD_TESTS=ON`: Enable building tests
- `-DBUILD_DOC=ON`: Enable building documentation
- `-DCOVERAGE=ON`: Enable code coverage (requires `-DBUILD_TESTS=ON`)
- `-DDEBUG=ON`: Build with debug symbols
- `-DSTATIC=ON`: Build static library

Example with all options:
```bash
cmake -DBUILD_TESTS=ON -DBUILD_DOC=ON -DCOVERAGE=ON -DDEBUG=ON .
```

## Installation

After building, you can install the library system-wide:
```bash
sudo make install
```

This will install:
- The library (`libldfl.so`) to `/usr/local/lib/`
- The wrapper executable (`ldfl-cli`) to `/usr/local/bin/`

## Usage

### Basic Usage

1. Create a configuration file (e.g., `config.json`) with your mapping rules:
```bash
ldfl-cli -c config.json -- your-application [args...]
```

## Configuration Options

The configuration file is a JSON file with two main sections: `settings` and `mappings`.

### Settings

The `settings` section controls the logging behavior:

```json
{
  "settings": {
    "log_mask": [
      "mapping_rule_found",
      "fn_call",
      "init",
      "mapping_rule_apply",
      "mapping_rule_search",
      "fn_call_err"
    ],
    "log_level": "warning",
    "logger": "syslog"
  }
}
```

Available log masks:
- `mapping_rule_found`: Log when a mapping rule is found
- `fn_call`: Log LibC function calls
- `init`: Log initialization operations
- `mapping_rule_apply`: Log when a mapping rule is applied
- `mapping_rule_search`: Log mapping search operations
- `fn_call_err`: Log LibC function call errors

Log levels:
- `debug`
- `info`
- `warning`
- `error`

Loggers:
- `syslog`: System logger
- `stderr`: Standard error output
- `dummy`: No logging

### Mappings

The `mappings` section defines the file path remapping rules. Each mapping has the following properties:

```json
{
  "mappings": [
    {
      "name": "descriptive name",
      "search_pattern": "regex pattern",
      "operation": "operation type",
      "target": "target path or resource",
      "path_transform": "absolute|original",
      "extra_options": "operation specific options"
    }
  ]
}
```

#### Available Operations

1. **File Redirection** (`map`):
```json
{
  "name": "temp files redirect",
  "search_pattern": ".*/temp/([^/]*)$",
  "operation": "map",
  "target": "/tmp/$1",
  "path_transform": "absolute"
}
```

2. **Executable Redirection** (`exec_map`):
```json
{
  "name": "executable redirect",
  "search_pattern": ".*/.bin/\\([^/]*\\)$",
  "operation": "exec_map",
  "target": "/opt/ldfl/bin/\\1",
  "path_transform": "absolute"
}
```

3. **Memory File** (`mem_open`):
```json
{
  "name": "memory open",
  "search_pattern": ".*/file[0-9].txt",
  "operation": "mem_open",
  "target": null,
  "path_transform": "absolute"
}
```

4. **Static File** (`static`):
```json
{
  "name": "static file",
  "search_pattern": ".*/static.bin",
  "operation": "static",
  "target": "default_blob",
  "path_transform": "absolute"
}
```

5. **Permission Change** (`perm`):
```json
{
  "name": "change data perm",
  "search_pattern": ".*/data/.*",
  "operation": "perm",
  "target": null,
  "path_transform": "absolute",
  "extra_options": "user:group|dir_mode|file_mode"
}
```

6. **Access Control**:
   - **Allow** (`noop`):
```json
{
  "name": "allow /dev",
  "search_pattern": "^/dev/.*",
  "operation": "noop",
  "path_transform": "absolute"
}
```
   - **Deny** (`deny`):
```json
{
  "name": "default & deny",
  "search_pattern": ".*",
  "operation": "deny",
  "path_transform": "absolute"
}
```

7. **Read-Only** (`ro`):
```json
{
  "name": "read only files",
  "search_pattern": ".*/readonly/.*",
  "operation": "ro",
  "path_transform": "absolute"
}
```

### Debug Mode

To enable debug output, use the `-d` flag:
```bash
ldfl-cli -d -c config.json -- your-application [args...]
```

### Custom Library Path

If you need to specify a custom library path:
```bash
ldfl-cli -l /path/to/libldfl.so -c config.json -- your-application [args...]
```


