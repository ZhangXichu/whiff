## Whiff

A very lightweight wifi handshake analyzer and WPA2 cracker toolkit. It captures and processes `.pcap` files to extract WPA2 4-way handshakes and generate `.hc22000` files as input to hashcat.


### dependencies

- `libcap` 
- `loguru`

### install conan packages and build project

1. run `setup_venv.sh` to prepare the virtual environment and install `conan`
2. activate virtual environment
    ```bash
    source .venv/bin/activate
    ```
3. build project
    ```bash
    conan install . --output-folder=build --build=missing -s build_type=Debug
    
    cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake -DCMAKE_PREFIX_PATH=build   -DCMAKE_BUILD_TYPE=Debug

    cmake --build build
    ```

### usage

capture packets and dump EAPOL packets to output file `output.pcap`
```
./whiff --capture <interface> <output.pcap>
```
prepare input into Hash
```
./whiff --export <interface> <output.pcap>
```

### future
- support for crecking wifi password using PMKID. This is not done yet because I didn't manage to trigger packets with PMKID. So I don't have packets for testing.