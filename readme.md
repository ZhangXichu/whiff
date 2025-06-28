## Whiff

A lightweight wifi handshake analyzer and WPA2 cracker toolkit. It captures and processes `.pcap` files to extract WPA2 4-way handshakes and generate `.hc22000` files as input to hashcat.


### dependencies

- `libcap` 


### build
```bash
mkdir build
cd build
cmake ..
make
```