# LDFL

[![Doxygen](https://github.com/kakwa/ldfl/actions/workflows/doxygen.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/doxygen.yml)
[![Memleak Check](https://github.com/kakwa/ldfl/actions/workflows/valgrind.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/valgrind.yml)
[![Unit Tests & Coverage](https://github.com/kakwa/ldfl/actions/workflows/coverage.yml/badge.svg)](https://github.com/kakwa/ldfl/actions/workflows/coverage.yml)
[![codecov](https://codecov.io/gh/kakwa/ldfl/graph/badge.svg?token=08AAHC625O)](https://codecov.io/gh/kakwa/ldfl)

## Presentation

LDFL (LD File Liar) is a `LD_PRELOAD` library to remap file and directory path.

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
cmake -DBUILD_TESTS=ON -DBUILD_DOC=ON -DCOVERAGE=ON -DDEBUG=ON ..
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
```json
{
    "mappings": [
        {
            "name": "example",
            "search_pattern": "/path/to/original/file",
            "operation": "map",
            "target": "/path/to/new/location",
            "path_transform": "abs"
        }
    ]
}
```

2. Use the wrapper to run your application:
```bash
ldfl-cli -c config.json -- your-application [args...]
```

## Configuration Options

Each mapping can have the following properties:
- `name`: Descriptive name for the mapping
- `search_pattern`: Regular expression pattern to match files
- `operation`: Type of operation to perform
- `target`: Target path or resource
- `path_transform`: Use "orig" for original path or "abs" for absolute path
- `extra_options`: Additional options specific to the operation

The configuration file supports several operations:
- `map`: Map a file to a different location
- `exec_map`: Map an executable to a different location
- `mem_open`: Open a file from memory
- `static`: Static file operation
- `perm`: Change file permissions/ownership
- `deny`: Deny access to a file
- `ro`: Restrict to read-only access

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


