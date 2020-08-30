#!/bin/bash
frida-compile jni.ts -o a.js
frida --no-pause -U --runtime=v8 -l a.js -f  com.zhiliaoapp.musically
