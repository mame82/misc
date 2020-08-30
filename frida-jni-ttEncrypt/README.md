# Some JNI experiments with Frida

Test of hooking of JNI methods which are not exported by the the native library, but registered with `registerNatives`.

Example targets `ttEncrypt` function exposed by TikTok in the `com.bytedance.frameworks.encryptor.EncryptorUtil` class. The respective hook is placed by the `hookIfTTEncrypt` function (which
could be replaced for other scenarios and serves as example for dynamic hooking once an intended native method gets registered).

The input for the `ttEncrypt` function gets printed to the console as hexdump, but is not human readable because it contains a gzip stream (unless it is data from a crashdump)

# install

The script is written in typescript and thus has to be compiled with `frida-compile` before use. `test.sh` gives an example on how to do this.

To install frida-compile:

```
npm install -g frida-compile
```

Assuming a Android device with TikTok and frida-server installed is attached via USB, the script could be deployed like this:

```
frida-compile jni.ts -o agent.js
frida --no-pause -U --runtime=v8 -l agent.js -f com.zhiliaoapp.musically
```
