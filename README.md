# knockd
A simple port knocking daemon written in C++

# Building
```sh
export CPP=your-compiler-of-choice FILE_INCLUDES='-I/path/to/libpcap/include' LINK_INCLUDES='-L/path/to/libpcap/lib'

make
```

# Running

## Using a ports file
- Echo out the port sequence into a file, then feed it to knockd (one port per line):
```sh
echo '22
23
24
25
26
' > ports

# listen on eth0 for udp, and read ports from file 'ports'
./knockd eth0 udp < ports
```

## Listening for tcp traffic
```sh
./knockd eth0 tcp < ports
```

## Listening for udp traffic
```sh
./knockd eth0 udp < ports
```

## Randomly generate a sequence
```sh
./knockd eth0 udp generate
```

If you use `generate`, the first line `knockd` will output is a forward slash delimited port sequence:
```sh
./knockd eth0 udp generate
seq:38656/38656/63/38719/30133/33320/9098/23514/61394/6970/58868/56864/59273/45912/62491/24507/13472/23335/16725/62735/34407/30533/60090/6046/298/29373/21261/51207/23639/52451/8629/17500/27659/59820/20090/63752/20513/27063/9506/62447/32849/57528/37362/53116/12028/23487/15090/9634/23470/15235/35448/25327/10179/46767/6312/11067/42433/51563/41099/59309/22/61848/13873/14303/
```

