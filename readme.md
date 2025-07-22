## Whiff

A very lightweight wifi handshake analyzer and WPA2 cracker toolkit. It captures and processes `.pcap` files to extract WPA2 4-way handshakes and generate `.hc22000` files as input to hashcat.


### dependencies

- `libcap` 


### build
```bash
mkdir build
cd build
cmake ..
make
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