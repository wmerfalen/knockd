# knockd
A simple port knocking daemon written in C++

# Building
```sh
export CPP=your-compiler-of-choice FILE_INCLUDES='-I/path/to/libpcap/include' LINK_INCLUDES='-L/path/to/libpcap/lib'

make
```

# Running

## Listen on `eth0` for `udp` packets. Read from `stdin`
```sh
./knockd -i eth0 -p udp -s < ports
```

## Specifying a file to read port sequence from
```sh
./knockd -i eth0 -p udp -f ports

# the above is equivalent to
./knockd -i eth0 -p udp -s < ports
```

## Listen on `eth0` for `tcp` packets. Randomly generate sequence and write to file named `generated`
```sh
./knockd -i eth0 -p tcp -g generated
```
- The file `generated` can be re-used now. The following two commands are equivalent:
```sh
./knockd -i eth0 -p tcp -s < generated

# or
./knockd -i eth0 -p tcp -f generated
```

## Format of generated port sequences
If you use `-g file`, a port sequence will be written to `file`. 64 ports will be written. One port per line.
The file will have linux newlines (`\n`). 

# Future as a library
Core functionality has been moved to `lib/knockd.hpp`.
It is possible to use this file as a header-only import in your projects.
The example code is in `main.cpp`.
At some point, I'll get around to creating doxygen documentation for the library interface.

# Version
`v2.0.0`
