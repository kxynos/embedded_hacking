## Overriding fopen to change the file that will be read - changing args

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

If you try replacing the input arguments via args you will have to replace the current one (the address) with a new one. We do this by assigning a new value to args[0], as per Frida's Best Practice. 

Therefore, a new path has to be stored in memory. This is accomplished as follows:

```js
var new_path = Memory.allocUtf8String("sometext2.txt");
args[0] = new_path
```

So the final Python script will look like this. You will notice that the hooking is much more simple and it gets the  

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

Interceptor.attach(fopen_address, {
    onEnter: function(args) {
            var new_path = Memory.allocUtf8String("sometext2.txt");
            this.new_path = new_path;
            console.log("[*] path: " +  Memory.readCString(args[0]));
            if (path.endsWith('sometext.txt')) {
            args[0] = new_path
            }
            console.log("[*] new path: " +  Memory.readCString(args[0]));
    }
});

""")
script.on("message", on_message)
script.load()
frida.resume(pid)
sleep(0.5)
session.detach()
```

If you are successful you should get the following results:

```bash
$ python3 frida-args-read4.py 
[*] fopen_address at : 0x7f34a73e8740
[*] path: sometext.txt
[*] new path: sometext2.txt
Value of n=4
```


####Commands tested using 

```
$ frida --version
12.8.20
```
