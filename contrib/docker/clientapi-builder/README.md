This image will fully build the backend (`zcoind`) for every OS, and following the instructions below, build the rich GUI for Windows and Linux.
For Mac, building the rich GUI requires a MacOS operating system. This is a requirement of Electron. If this changes in future to allow building on an Ubuntu image, the instructions here will be updated.

### Build Rich GUI (Windows and Linux)
```
cd zcoin
```

#### make Linux
```
make distclean && \
./autogen.sh && \
./configure --prefix=$(pwd)/depends/x86_64-unknown-linux-gnu --enable-clientapi ----enable-crash-hooks --disable-gui && \
make clean && \
make -j`nproc`
```

#### copy binaries
```
cp src/zcoind ../zcoin-client/assets/core/linux
cp src/zcoin-cli ../zcoin-client/assets/core/linux
cp src/zcoin-tx ../zcoin-client/assets/core/linux
```

#### make Windows
```
make distclean && \
./autogen.sh && \
./configure --prefix=$(pwd)/depends/x86_64-w64-mingw32 --enable-clientapi ----enable-crash-hooks --disable-gui --enable-reduce-exports && \
make clean && \
make -j`nproc`
```

#### copy binaries
```
cp src/zcoind.exe ../zcoin-client/assets/core/win32
cp src/zcoin-cli.exe ../zcoin-client/assets/core/win32
cp src/zcoin-tx.exe ../zcoin-client/assets/core/win32
```

### Build
```
cd ../zcoin-client && npm run build
```

### Build Mac
```
cd ../zcoin
```

#### make Mac

```
make distclean && \
./autogen.sh && \
./configure --prefix=$(pwd)/depends/x86_64-apple-darwin11 --enable-clientapi ----enable-crash-hooks --disable-gui && \
make clean && \
make -j`nproc`
```

#### setup local zcoin-client (requires MacOS operating system, tested working on Catalina)
```
git clone https://github.com/zcoinofficial/zcoin-client/
mkdir zcoin-client/assets/core/darwin
```

#### get this docker container ID
```
sudo docker ps
```

#### copy binaries locally
```
sudo docker cp {CONTAINER_ID}:/home/zcoin-client-builder/zcoin/src/zcoind zcoin-client/assets/core/darwin
sudo docker cp {CONTAINER_ID}:/home/zcoin-client-builder/zcoin/src/zcoin-cli zcoin-client/assets/core/darwin
sudo docker cp {CONTAINER_ID}:/home/zcoin-client-builder/zcoin/src/zcoin-tx zcoin-client/assets/core/darwin
```

#### Edit file `zcoin-client/package.json` to only build for MacOS
```
sed -i "s/-mlw/-m/" zcoin-client/package.json
```

### Build
```
cd zcoin-client && npm run build
```

#### troubleshooting
- If you have issues with `zeromq` and `node-sass`, please try the following:
```
rm -rf node_modules
npm install zeromq
npm uninstall --save-dev node-sass
npm install --save-dev node-sass
npm run build
```
