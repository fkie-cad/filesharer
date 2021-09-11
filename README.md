# TCP Fileshare client and server
Cross Os (Linux/Windows) Fileshare client and server.  

Currently, working just one-way and not bidirectional.

Encryption is supported, but still in experimental state.

Warning: 
This tool at some stages has been flagged as a positive threat by Windows Defender for unknown reasons. 
To prevent this, drop this tool in an "exclusion" folder.


## Version ##
1.3.15  
Last changed: 11.09.2021


## Requirements
### Linux ###
- Openssl library
- gcc
- [cmake]

### Windows ###
- msbuild 
- [WDK]

**Remarks**  
The .vcxproj file is using `WindowsApplicationForDrivers10.0` as the `PlatformToolset`, which leads to smaller builds. 
If the WDK is not installed, the `PlatformToolset` may be changed to `v142` and it should compile without errors.


## Build

### Windows msbuild in normal cmd
```bash
$ winBuild.bat [/t all|server|client] [/b 32|64] [/m Debug|Release] [/mt no|Release|Debug]  [/?]
```

### Windows msbuild in developer cmd
```bash
$devcmd> msbuild [server.vcxproj|client.vcxproj] [/p:Platform=x86|x64] [/p:Configuration=Debug|Release] [/p:RunTimeLib=Debug|Release]
```

### Linux gcc + cmake 
```bash
$ ./linuxBuild.sh [-t all|server|client] [-m Debug|Release] [-h]
```

### Linux gcc plain
```bash
$ mkdir build
$ gcc -o build/FsClient -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Ofast -L/usr/lib -lcrypto src/client.c shared/*.c shared/collections/*.c shared/crypto/linux/*.c shared/files/Files.c shared/files/FilesL.c shared/net/sock.c shared/net/linSock.c src/FsHeader.c -Ishared  
$ gcc -o build/FsServer -Wl,-z,relro,-z,now -D_FILE_OFFSET_BITS=64 -Ofast -L/usr/lib -lcrypto src/server.c shared/*.c shared/collections/*.c shared/crypto/linux/*.c shared/files/Files.c shared/files/FilesL.c shared/net/sock.c shared/net/linSock.c src/FsHeader.c -Ishared  
```
Use `clang` instead of `gcc` in Termux on Android.

## Run
### Server
**Usage:**
```bash
$ server port dir [-i 4|6] [-k path/to/priv.key]
```
**Options:**
 - port:uint16 : The listening port number of the server.
 - dir:string : A directory to store the files in. 
 - -i : IP version 4 (default) or 6. 
 - -k : Path to an (unencrypted) private RSA key (Windows: .der, Linux: .pem) file to decrypt encrypted data from the client. 
 
**Example:**
plain
```bash
$ server 8080 %tmp%
```
encrypted
```bash
$ server 8080 %tmp% -k dir\key.der
```

### Client
**Usage:**
```bash
$ client ip port [-c] [-r] [-f] [-i 4] [-k path/to/pub.key] path [an/other/path ...]
```
**Options:**
 - ip:string : Dotted ip address of the server.
 - port:uint16 : The listening port number of the server.
 - -c : Check hashes of files, after being transferred. Default if transferred encrypted.
 - -r : Copy directories recursively.
 - -f : Flatten copied directories, i.e. copy all files to base dir. Only meaningful if /r is set.
 - -i : IP version 4 (default) or 6.
 - -k : Path to a public RSA key (Windows: .der, Linux: .pem) file used to encrypt the data.
 - path:string[] : One or more paths of files or directories to be sent.
 
**Example:**  
Two files, no hash check
```bash
$ client 127.0.0.1 8080 file1 file2
```
Two files with hash check
```bash
$ client 127.0.0.1 8080 -c file1 file2
```
Copy directory recursivly
```bash
$ client 127.0.0.1 8080 -r a/dir
```
encrypted
```bash
$ client 127.0.0.1 8080 -k dir/key.pem file1 file2
```


### Runtime Errors (Windows)
If a "VCRUNTIMExxx.dll not found Error" occurs on the target system, statically including LIBCMT.lib is a solution.  
This is done by using the `/p:RunTimeLib=Debug|Release` (msbuild) or `[/mt Release|Debug]` (winBuild) flags.


### Encryption
Encryption is done by RSA (PKCS1 padding) and AES256 in CBC mode.
The AES secret and IV is first sent encrypted with the public RSA key and then the file header and data is sent encrypted with the AES key.
The client has to pass a public RSA (Windows: .der, Linux: .pem) key to which the server owns the corresponding private (Windows: .der, Linux: .pem) key.
The communication partners have to know each other beforehand and obviously both have to provide a key or none of them.
There is no key exchange happening like e.g. in TLS.  

Currently, the private key has to be stored unencrypted as a file on the server system.  
On Windows it has to be in `.der` format, on Linux in `.pem` Format.

For each file a new AES key and IV is created.
On the other hand, there is only one IV created but used for sending the file header, the data and the answers.
To ensure security, an AES block sized random buffer is added to the file header and the answers so that the IV is not consumed before sending the data.  
This may be changed, if a better solution is found.

Since the file has to be encrypted as a whole, again to don't consume the IV, there may be limits to its size if memory is low.
This may be changed though in future versions.
The buffer length type for `BCryptEncrypt` is ULONG which leads to a maximum size of max(ULONG) on this end.
Bigger files may be transmitted split.

RSA padding will be changed to AOEP in the future, when it's implemented correctly working on Windows.  
AES block cipher mode may be changed too to GCM.


### Integrity
The file data itself is checked by its sha256 hash. 
Integrity checks for the headers and maybe the answers aswell will be added in future versions.


## COPYRIGHT, CREDITS & CONTACT ## 
Published under [GNU GENERAL PUBLIC LICENSE](LICENSE).

#### Author ####
- Henning Braun ([henning.braun@fkie.fraunhofer.de](henning.braun@fkie.fraunhofer.de)) 
