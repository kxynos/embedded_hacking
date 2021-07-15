## Overriding fopen to change the file that will be read

There is a simple program that uses fopen to read one character from a file named *sometext.txt*. We aim to load a different file instead. 

Save the following into a file titled *read_file.c*:

```c
// code from : https://www.programiz.com/c-programming/c-file-input-output
#include <stdio.h>
#include <stdlib.h>

int main()
{
   int num;
   FILE *fptr;

   if ((fptr = fopen("sometext.txt","r")) == NULL){
       printf("Error! opening file\n");

       // Program exits if the file pointer returns NULL.
       exit(1);
   }

   fscanf(fptr,"%d", &num);

   printf("Value of n=%d\n", num);
   fclose(fptr); 
  
   return 0;
}
```
Compile it:

```bash
gcc -o read_file read_file.c
```

Create a file *sometext.txt* with one line in it:
```
1
```

Create a second file *sometext2.txt* with one line in it:
```
2
```

The output should look like the following: 
```bash
$ ./read_file 
Value of n=1
```

**Aim** : load and print the contents from a file that you control. 

I found that the one way to go about completing this is by replacing the function and then replacing the argument with a new one. This is what is shown here. 

It is also possible to assign a new value to args[0] but you have to be careful and avoid access violations. Check the other write up on how it is done ([replacing_file_path_fopen_args.md](https://github.com/kxynos/embedded_hacking/blob/master/frida/replacing_file_path_fopen_args.md)). 

Therefore, a new path has to be stored in memory. This is accomplished as follows:
```js
var newPath = Memory.allocUtf8String("sometext2.txt");
pathPtr = ptr(newPath);
```

There is a check to see if the extension is .txt so we don't replace all the files that use fopen when we execute our program and frida scripts. 

```python
from __future__ import print_function
import frida
import sys
from time import sleep

def on_message(message, data):
    print(message)

pid  = frida.spawn("read_file")
session = frida.attach(pid)
script = session.create_script("""
var fds = {};
const fopen_address = Module.findExportByName(null, 'fopen');
console.log("[*] fopen_address at : " + fopen_address);

var open = new NativeFunction(fopen_address, 'pointer', ['pointer', 'pointer']);
Interceptor.replace(fopen_address, new NativeCallback(function (pathPtr, flags) {
  var path = pathPtr.readUtf8String();

  if (path.endsWith('.txt')) {
    var newPath = Memory.allocUtf8String("sometext2.txt");
    pathPtr = ptr(newPath);
  }
  var path = pathPtr.readUtf8String();
  console.log('Opening "' + path + '"');
  var fd = open(pathPtr, flags);
  console.log('Got fd: ' + fd);
  return fd;
}, 'pointer', ['pointer', 'pointer']));


""")
script.on("message", on_message)
script.load()
frida.resume(pid)
sleep(0.5)
session.detach()
```

If you are successful you should get the following results:
```bash
$ python3 frida-read4.py 
[*] fopen_address at : 0x7ffff7e69740
Value of n=2
Opening "sometext2.txt"
Got fd: 0x555555559b10
Opening "/dev/urandom"
Got fd: 0x7ffff0003300
```


####Commands tested using 

```
$ frida --version
12.8.20
```
