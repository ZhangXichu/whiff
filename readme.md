# Whiff

A very lightweight wifi handshake analyzer and WPA2 cracker toolkit. It captures and processes `.pcap` files to extract WPA2 4-way handshakes and generate `.hc22000` files as input to hashcat.


## Dependencies

- `libcap` 
- `loguru`

## Install conan packages and build project

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

## usage

### 📡 List Access Points

Scan the current wifi channel for visible access points (APs). This mode passively listens for beacon frames and logs the SSID and BSSID of each detected AP on the current channel.

Press Ctrl+C when you’re done scanning to print the list.

```
sudo ./whiff --list <interface>
```

### 📡 Capture packets 

Capture packets from a specific SSID and dump EAPOL packets to output file `output.pcap`. Note that the ssid must be provided because hidden networks are not supported. Whiff firstly attempts to detect the access point (AP) and then listens for EAPOL packets to capture the 4-way handshake. 

Once you believe the handshake has been captured (typically after a client connects or reconnects), press `Ctrl+C` to stop the capture and the results will be written to the output `.pcap` file.
```
sudo ./whiff --capture <interface> --output <file.pcap> --ssid <network_name>
```
Of course, the `.pcap` file can also be used with other tools that process EAPOL packets.

### 📤 prepare input for Hashcat

Extract handshakes from a `.pcap` and generate a `.hc22000` file, which can be consumed by Hashcat.
```
./whiff --export <interface> --input <file.pcap> --output <file.22000> --ssid <network_name>
```
The command above writes a Hashcat-compatible file to `<file.22000>` (you can name it anything — the `.22000` suffix is optional). And the input file `<file.pcap>` is the output file you acquired in the previous step.

## Logging
- log file is written to: `log/whiff.log`.
- Console log level is `INFO`.
- File log level is `loguru::Verbosity_MAX` which logs everything.

Note that if the `log/` folder is not writable or owned by root, you may encounter a "Failed to open". You can just use `sudo` to run the commands or fix with 

```bash
sudo chown -R $USER log
```


### Future plans
- support for crecking wifi password using PMKID. This is not done yet because I didn't manage to trigger packets with PMKID. So I don't have packets for testing.
- make whiff more automatic. For example stop after sufficient EAPOL packets are detected.