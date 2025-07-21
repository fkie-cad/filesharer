# TCP Fileshare client and server
Cross Os (Linux/Windows) Fileshare client and server.  

Encryption is supported, but still in experimental state.

Warning: 
This tool at some stages has been flagged as a positive threat by Windows Defender for unknown reasons. 
If this happens, drop this tool in an "exclusion" folder.

Compiles and runs under
- Linux 
- Windows (x86/x64)  
- Android in Termux
- OsX may work too


## Version ##
1.4.3  
Last changed: 11.01.2024


## Requirements
### Linux ###
- gcc
- Openssl (dev) library (openssl-dev, libssl-dev or sth. like that)

### Windows ###
- msbuild 


## Build

### Windows msbuild in normal or developer cmd

```bash
$ winBuild.bat [/app] [/m <Release|Debug>] [/b <32|64>] [/rtl] [/pdb] [/bt <path>] [/pts <PlatformToolset>] [/h]
```

The PlatformToolset defaults to "v142" but may be changed with the `/pts` option.
"v142" is used for VS 2019, "v143" would be used in VS 2022.

### Runtime Errors (Windows)
If a "VCRUNTIMExxx.dll not found Error" occurs on the target system, statically including the runtime libraries is a solution.  
This is done by using the `/p:RunTimeLib=Debug|Release` (msbuild) or `/rtl` (winBuild.bat) flag.


### Linux gcc
```bash
$ ./linuxBuild.sh [-t app] [-d|-r] [-h]
```

### Linux gcc plain
```bash
$ mkdir build
$ gcc -o build/FShare -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Ofast src/fshare.c src/client.c src/server.c shared/collections/*.c shared/crypto/linux/*.c shared/files/Files.c shared/files/FilesL.c shared/net/sock.c shared/net/linSock.c src/FsHeader.c -Ishared -L/usr/lib -lssl -lcrypto 
```

`-L/usr/lib -lssl -lcrypto` may be placed behind -Ofast, if linking errors occur.
Placing it at the end seems to be the most reliable option.

The openssl libs may not be located in `/usr/lib` but in `/usr/lib/x86_64-linux-gnu`, so `-L/usr/lib` has to be changed in that case.

Use `clang` instead of `gcc` in Termux on Android.


## Usage
```bash
Usage: FShare -recv <port>|-send <ip> <port> [-v <version>] [-k <path>] [-c] [-r] [-f] [-s <size>] <path> [...]
```

**Options**
- -recv: Start a receiving server on `<port>`.
- -send: Start a sending client to `<ip>` on `<port>`.
- -v: IP version 4 (default) or 6.
- -k: Path to an SSL key file to encrypt or decrypt data.
      The server has to use the private key, the client the public key.

**Server only options:**
- path: The existing target base directory, the shared files are stored in.

**Client only options:**
- -c : Check file hashes of transmitted files. 
       Set by default, if transferred encrypted.
- -r : Copy dirs recursively.
- -f : Flatten copied dirs to base dir. 
       Only used if /r is set.
- -s : Maximum size of encrypted chunk. 
       Has to be greater than 0x1000 and less than 0xFFFFFFFF.
       Defaults to 0x100000.
- path : One or more paths to files or directories to be sent.
    

## Examples:
Run plain server with ipv4 listening on port 1234 and save files in "files/"
```bash
$ FShare -recv 1234 files/
```

Run encrypted server with ipv6 listening on port 1234 and save files in "files/"
```bash
$ FShare -recv 1234 -v 6 -k .ssl/priv.key files/
```

Run plain ipv4 client, sending files file1 and file2 and checking the hashes
```bash
$ FShare -send 127.0.0.1 1234 -c file1 file2
```

Run encrypted ipv6 client, sending the directory "files" recursively
```bash
$ FShare -send 127.0.0.1 1234 -v 6 -c -k .ssl/pub.key -r files
```

Obviously, if the server expects encrypted files (i.e. the `-k <path>` option is set), 
the client has to send encrypted files (i.e. set the `-k <path>` option).


### Performance
Files are sent in chunks of 0x100000 byte blocks. 
The block size may be changed with the `-s` option in client mode.
The server will adopt this value.

If memory is low, this value may be decreased, at least down to 0x1000.

After each block, the client waits for an answer of the server, which slows down the process.
To speed up the transfer, the value may be increased (theoretically) up to 0xFFFFFFFF. 
The upper limit comes due to the MS BCrypt limit, that expects a ULONG (32-bit uint) as the length value in en/decryption functions.


### Encryption
Encryption is done by RSA (PKCS1 padding) and AES256 in CBC mode.
An AES secret and IV as randomly created for each file.
The AES secret and IV is encrypted with the public RSA key and sent to the server.
Then the file header and data is sent over encrypted with the AES key.
The client has to use a public RSA (Windows: .der, Linux: .pem) key to which the server owns the corresponding private (Windows: .der, Linux: .pem) key.
The communication partners have to know each other's keys beforehand and obviously both of them have to provide a key or none of them.
There is no key exchange happening like e.g. in TLS.  

Currently, the private key has to be stored unencrypted as a file on the server system.  
On Windows it has to be in `.der` format, on Linux in `.pem` Format.

For each file a new AES key and IV is created.
On the other hand, there is only one IV created but used for sending the file header, the data and the answers.
To ensure security, an AES block sized random buffer is added to the file header and the answers so that the IV is not consumed before sending the data.  
This may be changed, if a better solution is found.

RSA padding will be changed to AOEP in the future. 
AES block cipher mode may be changed too to GCM.

Files are sent in chunks of 0x100000 (or whatever the `-s` option is set to) byte blocks. 
For each block, the IV is rotated, so it should be different for each block.


### Integrity
The file data itself is checked by its sha256 hash. 
Integrity checks for the headers and maybe the answers as well will be added in future versions when RSA signing is implemented correctly working on Windows.


### Create keys
```bash
$ openssl ...
```
There is a [createOpenSslCert.sh](scripts/createOpenSslCert.sh) for Linux and also for Windows: [createOpenSslCert.bat](https://github.com/fkie-cad/windowsScripts/blob/master/crypto/createOpensslCert.bat)


### Questions, bugs, problems, issues
Feel free to open an issue.



## COPYRIGHT, CREDITS & CONTACT ## 
Published under [GNU GENERAL PUBLIC LICENSE](LICENSE).


#### Author ####
- Henning Braun ([henning.braun@fkie.fraunhofer.de](henning.braun@fkie.fraunhofer.de)) 
