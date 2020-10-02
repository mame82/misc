/*
 * Android Binder hooking example by MaMe82
 *
 * I tried various approaches to hook Android's binder, all have benefits and shortcomings
 *
 * 1) Binder transactions are based on IOCTLs, the most basic and low level approach
 * would be to hook 'libc.so!ioctl'. Beside having to deal with a bunch of other IOCTLs
 * (for which the command IDs depend on the architecture), one has to isolate IOCTLs
 * which represent actual Binder **transactions**. This means:
 *  a) The parsed IOCTL command has to be BINDER_WRITE_READ (not BINDER_THREAD_EXIT etc)
 *
 *  b) The BinderReadWrite data structure, which referenced by the IOCTL data in such
 *  a case, contains write/read buffers. Those buffer have to be parsed, too, in order to determine
 *  the actual Binder commands/reply types. Only some of them represent actual Binder-transactions
 *  (namely BC_TRANSACTION, BC_REPLY, BR_TRANSACTION, BR_REPLY ...).
 *
 *  c) Once it is clear that there is a transaction, the data structure could be parsed further
 *  to obtain the actual transaction data. The raw data basically represents a native Parcel (a
 *  serialized/marshalled form of the objects transferred via Binder interfaces).
 *  The issue here is that parsing the Parcels require two things:
 *
 *  d) knowledge on the data format (part of the Binder interface definition which is not necessarily
 *  publicly available)
 *
 *  e) Using the native version of 'Parcel', which is based on C++ style objects, is less convenient
 *  then using the Parcel version from the Java layer (no need to define NativeFunction, no need to
 *  take care of architecture specific structure parsing ...)
 *
 *  f) The Binder transactions themselves could contain "serialized" Binder objects. The binder kernel
 *  driver does some magic, to re-construct the references for such "cross process code", if Binder
 *  objects are passed in transactions and get unmarshalled again. The approach of passing Binder objects
 *  via Binder transactions is very common. Example:
 *      - you want to retrieve Location updates from LocationManage
 *      - LocationManager itself is a wrapper for a Binder client interface, which communicates with the respective
 *      system service (which itself implements a Binder).
 *      - now, if you register for location updates, this is done by a Binder transaction (which again is transmitted
 *      as IOCTL). To be precise, this transaction would not really target the location service, but the service manager
 *      service, which once more implements a Binder to manage other Binder based services.
 *      - Let's simplify things a bit: Even if the request for location updates would be based on a direct Binder
 *      transaction from your "Location Client App", you can't receive the location updates in reply. This is because,
 *      the binder IPC transactions mimic synchronous behavior, there is no way to stream back data (location updates)
 *      asynchronously. In fact, a single transaction could be regarded as a IPC method call, which returns with a single
 *      result and blocks, till the call ended.
 *      - In order to deal with this in an asynchronous fashion, the common approach of "registering callbacks" has to be used.
 *      - And here comes the issue: How could you register a callback in another process, which implements a Binder?
 *      Answer: Your app implements a Binder itself (the Binder implementation has a Interface description on a higher layer,
 *      so IPC methods are well defined ... search for AIDL / IInterface for more details).
 *      - So now your app could expose callback methods, which could be used from other processes via Binder transactions.
 *      But how should the LocationManager know about your callback implementation ? This is where passing the Binder object
 *      via Binder transactions comes into play. You basically call a Binder method of the LocationManager which is meant to
 *      register a callback for location updates. This "registerCallback" method is called from your app using a Binder
 *      transaction. The binder transaction itself contains a marshalled Binder object in its transaction data.
 *      This marshalled binder object represents the runtime code parts of your app, which implement the actual callbacks.
 *      The binder driver does the magic to replace the serialized Binder object with proper references runtime references
 *      to your callback code once unmarshalling the transaction.
 *  This only touches the surface of complexity of Binder transactions, when being viewed from native code at IOCTL level.
 *
 *  Note: instead of 'libc.so!ioctl' a hook to 'libbinder.so!ioctl' could be used, if other IOCTLs
 *  are not of relevance (called less frequently).
 *
 *  The main benefits of the native approach:
 *  - great visibility, as you could basically hook all Binder transactions in scope
 *  - while it could get hard to parse Parcels transferred via Binder transaction, there is nothing which prevents
 *  you from inspecting the raw data. This gets tricky from the Java layer, especially if the transaction data contains
 *  Binder objects
 *
 * 2) There are several places to hook Binder transactions on the Java layer.
 * - it is easier to deal with transaction data and reply-data, as it is mostly represented by instances of
 * the Java 'Parcel' class, and you have all the methods to read from/write to the parcels right on your hand (
 * as they are exposed to Frida)
 * - it is less easy to hook all Binder related code, because a any Class could get a Binder if the 'android.os.IBinder'
 * interface gets implemented. There exists a basic implementation with 'android.os.Binder' with a nice hooking point
 * 'execTransact'. Yet, you can not assume that all Binder implementations use this code (think for native code, f.e.)
 * - Native IBinder objects are mostly wrapped into 'android.os.BinderProxy' instances. Hooking the method 'transact'
 * of this class, gives some great visibility into how an app communicates with system services (f.e. all the managers
 * like LocationManager, StorageManager, TelephonyManager ...). For example, I used this to inspect IPC calls to
 * `com.google.android.gms.ads.identifier.internal.IAdvertisingIdService` as there is no class of type
 * 'AdvertisingIdService' available a runtime, which could be hooked to monitor requests for the ADVERTISING_ID.
 * The respective method call to such an interface is encoded in an UInt32 code (the method 'generateAdvertisingId' is
 * represented by the number 13 for this interface). So if an interface definition is not available publicly (AIDL)
 * it requires some reversing, to make sense to the Binder transactions.
 * - So if you know about the definition of an interface, the Parcel data of Binder transactions on the Java layer
 * could easily get unmarshalled back to real objects (the respective Classes have to implement the Parcelable interface),
 * which allow further interaction.
 * - Anyways, most of the times looking at the raw transaction data is enough. Often UTF16 string are contained, which help
 * to makes sense out of the raw data already (f.e. the aforementioned ADVERTISING ID is represented as such a string
 * and thus could be read directly from raw data). In fact, for my use case it is not optimal to implement functionality
 * to unmarshall transaction data for each and every binder transaction. On the Java layer, the Parcel.marshall() method
 * was a great help for me, as it basically converts the Parcel object back to a raw ByteArray (similar to the native
 * representation). Unfortunately, this would not work Parcelled data which contains Binder objects, as it would end up in
 * an exception. This happens quite often ... as already mentioned, passing Binder objects is very common.
 *
 *
 * 3) The approach represented in this code, was the best fir for my needs. Basically I hooked the transact method
 * of the native Binder implementation (BBinder::transact). This combines the benefits (and some shortcomings) of
 * my other approaches:
 * - there is no need to deal with IOCTL level stuff, as the hooked method already receives Parcel instances
 * - there are no issues with reading raw Parcel data if it includes Binder objects, because the hook targets
 * the native Parcel implementation (C++ version) not the Java version
 * - ?almost? all Binder transaction pass the hooked code (including those representing PING commands to Binders)
 * - to deal with the native Parcels a dedicated class was included, beside exposing the 'dataSize()' and 'data()'
 * methods (which allow reading the raw marshalled parcel data of the Binder transactions), the class includes a
 * method 'javaInstance' which tries to instantiate a new Java version of the native Parcel object (if the hooked
 * call is attached to a JVM)
 * - the example code just prints out the raw Parcel content of the transaction data and reply (most transactions
 * do NOT receive a reply, as they are implemented one way). The example also prints the reference to the obtained Java
 * version of the parcel (if applicable) and invokes a Parcel-class member function (dataSize) from Java land
 * to show that this is possible.
 *
 *
 * To deploy the code, the exported method 'hookNativeBinder()' has to be called.
 * The code was only tested on a 32bit ARM device running Android 9.
 */

// Ref: https://android.googlesource.com/platform/frameworks/native/+/jb-dev/include/binder/Parcel.h
// Note:    The class uses a very naive RegExp approach to de-mangle CPP export names
//          It pays no attention on different compilers and assumes names mangled like processed
//          by the RegExP in the static method 'getExportByMethodName'
class CPPParcel {
  private thisAddr: NativePointer
  static libParcelExports: ModuleExportDetails[] | null
  static exportMap: Map<string, ModuleExportDetails> = new Map<
    string,
    ModuleExportDetails
  >()

  constructor(addr: NativePointer) {
    this.thisAddr = addr
  }

  private static getExportByMethodName(
    name: string
  ): ModuleExportDetails | null {
    if (!CPPParcel.libParcelExports) return null
    // the suffix 'E[RPabvfdji]' is a bit naive, in fact the whole RegEx based de-mangling is naive
    const re = new RegExp(
      `.*android[0-9]{1,3}Parcel[0-9]{1,3}${name}E[RPabvfdji]`
    )
    const matchingExports = CPPParcel.libParcelExports.filter(e =>
      e.name.match(re)
    )
    if (matchingExports.length === 1) {
      if (matchingExports[0].type !== "function") return null // do not assign if type is "variable"
      return matchingExports[0]
    }
    return null
  }

  public static initClass(libBinderExports: ModuleExportDetails[]) {
    const reParcel = /.*android[0-9]{1,3}Parcel.*/
    CPPParcel.libParcelExports = libBinderExports.filter(exp =>
      exp.name.match(reParcel)
    )

    const requiredExports = [
      "data",
      //"dataAvail",
      //"dataPosition",
      //"ipcData",
      //"ipcDataSize",
      "dataSize"
    ]

    for (let expName of requiredExports) {
      const exp = CPPParcel.getExportByMethodName(expName)
      if (exp) CPPParcel.exportMap.set(expName, exp)
      else
        console.log(
          `Can not find export for Parcel member function '${expName}'`
        )
    }

    /*
    let out = "Assigned exports for CPP Parcel class:\n"
    for (let [k, v] of CPPParcel.exportMap) {
      out += `\t${k}: ${JSON.stringify(v)}\n`
    }
    console.log(out)
    */
  }

  public dump(): string {
    const pData = this.data()
    const dataSize = this.dataSize()
    if (dataSize && pData) return hexdump(pData, { length: dataSize })
    return ""
  }

  public dataSize(): number {
    const dataSizeFuncExport = CPPParcel.exportMap.get("dataSize")
    if (!dataSizeFuncExport) return 0
    const funcDataSize = new NativeFunction(dataSizeFuncExport.address, "int", [
      "pointer"
    ])
    const result = funcDataSize(this.thisAddr)
    //console.log("DATA_SIZE RESULT:", result)
    return result as number
  }

  public data(): NativePointer | null {
    const dataFuncExport = CPPParcel.exportMap.get("data")
    if (!dataFuncExport) return null
    const funcData = new NativeFunction(dataFuncExport.address, "pointer", [
      "pointer"
    ])
    const result = funcData(this.thisAddr)
    //console.log("DATA RESULT:", result)
    return result as NativePointer
  }

  public javaInstance() {
    if (!Java.available) return null
    const clazzParcel = Java.use("android.os.Parcel")
    const nativePtr: number = (this.thisAddr as any).toUInt32()
    const parcelFromPool = clazzParcel.obtain(nativePtr)

    return parcelFromPool
  }
}

export function hookNativeBinder() {
  // reference: https://android.googlesource.com/platform/frameworks/native/+/jb-dev/libs/binder/Binder.cpp
  // ref2: https://android.googlesource.com/platform/frameworks/native/+/jb-dev/include/binder/IBinder.h
  enum EnumsIBinder {
    PING_TRANSACTION = 0x5f504e47, //B_PACK_CHARS('_','P','N','G'),
    DUMP_TRANSACTION = 0x5f444d50, // B_PACK_CHARS('_','D','M','P'),
    INTERFACE_TRANSACTION = 0x5f4e5446, // B_PACK_CHARS("_", "N", "T", "F"),
    SYSPROPS_TRANSACTION = 0x5f535052 // B_PACK_CHARS("_", "S", "P", "R")
  }
  const FLAG_ONEWAY = 0x00000001
  const FIRST_CALL_TRANSACTION = 0x00000001
  const LAST_CALL_TRANSACTION = 0x00ffffff

  const reBBinder_onTransact = /.*BBinder.*transact.*/
  const mBinder = Module.load("libbinder.so")
  const exportsLibbinder = mBinder.enumerateExports()
  const exportsBBinderTransact = exportsLibbinder.filter(expDetails =>
    expDetails.name.match(reBBinder_onTransact)
  )

  CPPParcel.initClass(exportsLibbinder)

  for (let exp of exportsBBinderTransact) {
    console.log(`Hooking ${exp.name} ...`)
    Interceptor.attach(exp.address, {
      onEnter(args) {
        try {
          this.binderInstance = args[0]
          this.code = (args[1] as any).toUInt32() // uint32_t
          this.pData = args[2]
          this.pReply = args[3]
          this.flags = (args[4] as any).toUInt32() // uint32_t
        } catch (e) {
          console.log("BBinder:transact hook exception:", e)
        }
      },
      onLeave(retVal) {
        try {
          const selfInstance = this.binderInstance // not used, would allow accessing other BBinder instance functionality
          const code = this.code as number // uint32_t
          const pData = this.pData as NativePointer
          const pReply = this.pReply as NativePointer
          const flags = this.flags as number // uint32_t
          const isOneWay = (flags & FLAG_ONEWAY) > 0

          const data = new CPPParcel(pData)
          const reply = new CPPParcel(pReply)

          // Log some info to console
          let out = `${exp.name} called (code=${code}, pData=${pData}, pReply=${pReply}, flags=${flags} (oneWay: ${isOneWay}))`

          if (data !== null && data.dataSize() > 0) {
            out += "\ndata:\n" + data.dump()
            // testing Java access
            const javaInstance = data.javaInstance()
            if (javaInstance) {
              out += "\nJava version of Parcel: " + javaInstance
              out +=
                "\nJava instance method Parcel.dataSize(): " +
                javaInstance.dataSize()
            }
          }

          if (reply !== null && reply.dataSize() > 0) {
            out += "\nreply:\n" + reply.dump()
          }
          console.log(out)
        } catch (e) {
          console.log("BBinder:transact hook exception:", e)
        }
      }
    })
  }
}
