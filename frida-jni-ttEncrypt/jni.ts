/*
 * Playing with Frida and automatic JNI hooking for methods native methods which are not
 * exported, but exposed using JINEnv->registerNatives
 *
 * Example deals wit com.bytedance.frameworks.encryptor.EncryptorUtil.ttEncrypt, signature ([Bi)[B
 *
 * Note: Signatures of JNI methods are not parsed, to auto-generate hooks
 */

const psz = Process.pointerSize

// https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/functions.html#GetArrayLength
// only methods of relevance
enum JNIEnvIdx {
  FindClass = 6,
  GetMethodID = 33,
  CallObjectMethod = 34,
  GetStringUTFChars = 169,
  GetArrayLength = 171,
  GetByteArrayElements = 184,
  GetByteArrayRegion = 200,
  RegisterNatives = 215
}

function getNativeAddress(idx: number, env?: NativePointer) {
  const JNIenv: NativePointer = env ? env : Java.vm.getEnv().handle
  return JNIenv.readPointer()
    .add(idx * psz)
    .readPointer()
}

Java.performNow(() => {
  /*
   * jsize GetArrayLength(JNIEnv *env, jarray array);
   */
  const pGetArrayLength = getNativeAddress(JNIEnvIdx.GetArrayLength)
  const funcGetArrayLength = new NativeFunction(pGetArrayLength, "int", [
    "pointer",
    "pointer"
  ])

  /*
   * jmethodID GetMethodID(JNIEnv *env, jclass clazz, const char *name, const char *sig);
   */
  const pGetMethodID = getNativeAddress(JNIEnvIdx.GetMethodID)
  const funcGetMethodID = new NativeFunction(pGetMethodID, "pointer", [
    "pointer",
    "pointer",
    "pointer",
    "pointer"
  ])
  function getMethodID(
    env: NativePointer,
    clazz: NativePointer,
    methodName: string,
    methodSig: string
  ): NativePointer {
    const pMethodName = Memory.allocUtf8String(methodName)
    const pMethodSig = Memory.allocUtf8String(methodSig)
    return funcGetMethodID(env, clazz, pMethodName, pMethodSig) as NativePointer
  }

  /*
   * NativeType *GetByteArrayElements(JNIEnv *env, ArrayType array, jboolean *isCopy);
   */
  const pGetByteArrayElements = getNativeAddress(JNIEnvIdx.GetByteArrayElements)
  const funcGetByteArrayElements = new NativeFunction(
    pGetByteArrayElements,
    "pointer",
    ["pointer", "pointer", "char"]
  )

  /*
   * const char * GetStringUTFChars(JNIEnv *env, jstring string, jboolean *isCopy);
   */
  const pGetStringUTFChars = getNativeAddress(JNIEnvIdx.GetStringUTFChars)
  const funcGetStringUTFChars = new NativeFunction(
    pGetStringUTFChars,
    "pointer",
    ["pointer", "pointer", "char"]
  )
  function getStringUTFChars(
    env: NativePointer,
    jstring: NativePointer,
    isCopy: boolean
  ): NativePointer {
    return funcGetStringUTFChars(env, jstring, isCopy ? 1 : 0) as NativePointer
  }

  /*
   * jclass FindClass(JNIEnv *env, const char *name);
   */
  const pFindClass = getNativeAddress(JNIEnvIdx.FindClass)
  const funcFindClass = new NativeFunction(pFindClass, "pointer", [
    "pointer",
    "pointer"
  ])
  function findClass(env: NativePointer, className: string): NativePointer {
    const res = funcFindClass(env, Memory.allocUtf8String(className))
    return res as NativePointer
  }

  /*
   * NativeType CallObjectMethod(JNIEnv *env, jobject obj, jmethodID methodID, ...);
   */
  const pCallObjectMethod = getNativeAddress(JNIEnvIdx.CallObjectMethod)
  const funcCallObjectMethod = new NativeFunction(
    pCallObjectMethod,
    "pointer",
    ["pointer", "pointer", "pointer", "..."] // additional arguments could be appended after jmethodID
  )
  function callObjectMethod(
    env: NativePointer,
    objectInstance: NativePointer,
    methodId: NativePointer,
    ...args: any[]
  ): NativePointer {
    return funcCallObjectMethod(
      env,
      objectInstance,
      methodId,
      ...args
    ) as NativePointer
  }

  // jclass for java.lang.Class
  const jclassClass = findClass(Java.vm.getEnv().handle, "java/lang/Class")
  console.log("global java.lang.Class: " + jclassClass)

  // jmethodID for java.lang.class.getName(): string
  const jmethodIdClassGetName = getMethodID(
    Java.vm.getEnv().handle,
    jclassClass,
    "getName",
    "()Ljava/lang/String;"
  )
  console.log("global java.lang.Class.getName(): " + jmethodIdClassGetName)

  function getUtf8NameForJClass(
    env: NativePointer,
    jclass: NativePointer
  ): string {
    // call java.lang.Class.getName() for the given class
    const jstringClassName = callObjectMethod(
      env,
      jclass,
      jmethodIdClassGetName
    )
    //console.log("ClassName ptr: " + jstringClassName)
    const pNativeUtf8Str = getStringUTFChars(env, jstringClassName, false)
    const utf8str = pNativeUtf8Str.readUtf8String()

    return utf8str ? utf8str : "unknown"
  }

  /*
   * jint RegisterNatives(JNIEnv *env, jclass clazz, const JNINativeMethod *methods, jint nMethods);
   *
   * typedef struct {
   *    char *name;
   *    char *signature;
   *    void *fnPtr;
   * } JNINativeMethod;
   *
   */
  const pRegisterNatives = getNativeAddress(JNIEnvIdx.RegisterNatives)
  Interceptor.attach(pRegisterNatives, {
    onEnter(args) {
      const env = args[0]
      const clazz = args[1]
      const pMethods = args[2]
      const nMethods = args[3].toInt32()

      const className = getUtf8NameForJClass(env, clazz)
      console.log(
        "registerNatives(class=" +
          className +
          ", pMethods=" +
          pMethods +
          ", nMethods=" +
          nMethods +
          ")"
      )

      // iterate over JNINativeMethod structs
      const sizeofJNINativeMethod = psz * 3
      for (let i = 0; i < nMethods; i++) {
        const pCurrentMethod = pMethods.add(sizeofJNINativeMethod * i)
        const pMethodName = pCurrentMethod.readPointer()
        const pMethodSig = pCurrentMethod.add(psz).readPointer()
        const pFunc = pCurrentMethod.add(psz * 2).readPointer()
        const methodName = pMethodName.readUtf8String()
        const methodSig = pMethodSig.readUtf8String()
        console.log("\t" + pFunc + ": " + methodName + " " + methodSig)
        hookIfTTEncrypt(className, methodName, methodSig, pFunc)
      }
    }
  })

  function hookIfTTEncrypt(
    className: string,
    methodName: string | null,
    methodSig: string | null,
    funcPtr: NativePointer
  ) {
    if (methodName !== "ttEncrypt") return
    if (methodSig !== "([BI)[B") return

    console.log(
      "\x1b[31;11mFound 'ttEncrypt' in class " +
        className +
        ", hooking ...\x1b[39;49;00m"
    )

    Interceptor.attach(funcPtr, {
      onEnter(args) {
        const env = args[0]
        const byteArray = args[2]
        const arrayLen = args[3]

        /*
        this.len2 = funcGetArrayLength(env, byteArray) // returns jint
        console.log(
          "called ttEncrypt(" + byteArray + ", " + arrayLen + ")" + this.len2
        )
        */

        // retrieve Native pointer to content of Array
        const pBuf = funcGetByteArrayElements(
          env,
          byteArray,
          0
        ) as NativePointer

        // ToDo: release array
        console.log(
          "raw InputBuffer for ttEncrypt (likely GZIP data magic 0x1f8b08)"
        )
        console.log(hexdump(pBuf, { header: true, length: arrayLen.toInt32() }))
      }
    })
  }

  // The following functions are commented out, because they aren't useful for
  // 'com.bytedance.frameworks.encryptor.EncryptorUtil'
  // they work anyways

  /*
  Interceptor.attach(pFindClass, {
    onEnter(args) {
      this.env = args[0]
      this.name = args[1].readUtf8String()
    },
    onLeave(ret) {
      console.log("findClass(" + this.env + ", " + this.name + ") => " + ret)
      return ret
    }
  })
  */

  /*
  // not used by ttEncrypt to fetch data
  const pGetByteArrayRegion = getNativeAddress(JNIEnvIdx.GetByteArrayRegion)
  Interceptor.attach(pGetByteArrayRegion, {
    onEnter(args) {
      this.start = args[2].toInt32()
      this.len = args[3].toInt32()
      this.buf = args[4]

      console.log(
        "getByteArrayRegion start=" +
          this.start +
          ", len=" +
          this.len +
          ", *buf=" +
          this.buf
      )
    },
    onLeave(retval) {
      console.log(hexdump(this.buf, { offset: this.start, length: this.len }))
      return retval
    }
  })
  */

  /*
  Interceptor.attach(pGetByteArrayElements, {
    onEnter(args) {
      this.array = args[1]
      // determine length of jarray
      this.len = funcGetArrayLength(args[0], this.array) // returns jint
      console.log(
        "getByteArrayElements array=" + this.array + " (len=" + this.len + ")"
      )
    },

    onLeave(pArrayBuf) {
      console.log(hexdump(pArrayBuf, { offset: 0, length: this.len }))
      return pArrayBuf
    }
  })
  */
})
