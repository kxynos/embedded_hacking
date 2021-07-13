## Some random Frida scripts 

### JS Script to hook into a custom function an iOS mobile application.  

I was starting frida manually (in interactive mode) and pasting this code in to see the results. You can copy it into a js file and feed it in with -l option.

```
frida -U -f com.company.package 
```

The script is targeting a binary called 'CustomBinaryName'. I have reversed engineered (RE) it and found that the function I am after is not an Objective-C one and therefore not exposed in that manner. Therefore, I need to find its location and hook into it that way. When reversing the application I found that the RE application was starting at `0x10000000` and the reported potision was `0x01030ccd0`, so I removed that based and got `0x30ccd0`. This is then added to the current 'moduleBase' that is retrieived. I am focusing on the incoming arguments of this function and trying to capture them. They are then saved to a file for processing later. Note that the file generated here is on the server's side so you will find `/tmp/arg.dump.bin` on the actual device. Find the binary `CustomBinaryName` in the package you want to debug. 


```js
var targetModule = 'CustomBinaryName';var addr = ptr(0x30ccd0);var moduleBase = Module.getBaseAddress(targetModule);var myFile = new File('/tmp/arg.dump.bin','wb');var targetAddress = moduleBase.add(addr);Interceptor.attach(targetAddress, {        onEnter: function(args) {            console.log("[!] Targeted function in CustomBinary is hooked at " + targetAddress);            console.log("[*] arg0: " +  args[0]);            console.log("[*] arg1: " +  args[1]);            console.log("[*] arg1 string: " + Memory.readCString(Memory.readPointer(args[1])));            var bbuf = Memory.readByteArray(Memory.readPointer(args[1]), 100);            console.log(bbuf);            myFile.write(bbuf);            console.log("[*] arg2: " +  args[2]);            console.log("[*] arg2 size: " + Memory.readPointer(args[2]).toInt32() );        }    });
    
```

Don't forget to also include `%resume` to resume execution. 

Like I said, this technique is useful when you want to hook into a function that is compiled into a binary and you don't have any obvious access to it, for instance via ObjC.

### JS Script to read data from an iOS system.  

This is a way to read files on an iOS device using `NSString[+ stringWithString:]`. Keep in mind that you can issue this commands after the program is unpaused (after `%resume`). 

```js
var NSString = ObjC.classes.NSString;
var path = NSString["+ stringWithString:"]("/tmp/import.bin");
console.log("[*] filePath: " +path);
var fileHandle = ObjC.classes.NSFileHandle['+ fileHandleForReadingAtPath:'](path);
console.log("[*] fileHandle: " + fileHandle);
var data = fileHandle['- readDataOfLength:'](1000)
var bytes = Memory.readByteArray(data.bytes(), data.length());
console.log("[*] bytes: " + bytes);
```

####Commands tested using 

```
$ frida --version
14.2.18
```
