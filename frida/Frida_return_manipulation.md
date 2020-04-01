## Create a binary and change the return value.

Let's try to hack the following binary using Frida. Return values are used quite often in programming and therefore it is a good thing to learn first. 

First create a binary in Linux.

Save the following into a file *testapp.c* : 

```
#include <stdio.h>
 
int main() {
    int b;
    printf("Hello, world!\n");
    testFunc1();
    b = testFunc2();

    printf("Returned value is : %d \n",b);

    return 0;
}

void testFunc1(){
printf("Test function 1 \n");
}

int testFunc2(){
printf("Test function 2 \n");
return 2;
}
```
Compile it into an executable:
```
 gcc -o testapp testapp.c
```
Execute the binary to see what output you get and that it all works. 
```
$ ./testapp
Hello, world!
test func 1 
test func 2 
Returned value is : 2 
```
**Aim:** To return 0 from function *testFunc2* instead of 2.

Get the offset of the function *testFunc2*. 

```
$ objdump -d testapp | grep -i "tes*"
... (removed assembly)
000000000000118d <testFunc1>:
00000000000011a0 <testFunc2>:
```

So we now know that it is located at position: **0x11a0**.

Let's start Frida and try some interactive commands so we can understand Frida a bit more. 

```
frida -f testapp
     ____
    / _  |   Frida 12.8.20 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://www.frida.re/docs/home/
Spawned `testapp`. Use %resume to let the main thread start executing!  
[Local::testapp]->                                                                        
```
Now to get the Base address for the application. We need this to calculate the actual address of the function *testFunc2*. With ASLR enbaled it will be different everytime the application runs. So we have to calculate it everytime. This is done with add().  

```
[Local::testapp]-> Module.findBaseAddress('testapp')                                                                           
"0x563be2666000"
```
We got my applications current Base address *0x563be2666000* and will add *0x11a0* next. 

```
[Local::testapp]-> Module.findBaseAddress('testapp').add(0x11a0)                                                               
"0x563be26671a0"
```

Pleace this into some python3 code. You can try this in the interactive console of Python3 or just save it in a file, e.g., *frida-testapp.py*.  

```
from __future__ import print_function
import frida
import sys
    
pid  = frida.spawn("testapp")
session = frida.attach(pid)

script = session.create_script("""
const testFunc2_loc = Module.findBaseAddress('testapp').add(0x11a0)
console.log("[*] testFunc2 at : " + testFunc2_loc);
""")

script.load()
frida.resume(pid)
session.detach()
```
Note: if you don't *detach*, you won't see the messages. 

The next thing we want to do is intercept the function and return a different value. *Interceptor.attach(func2, {* allows us to use interceptor to attach to the specified funciton. The *onLeave* has **retval** that we can then manipulate with *.replace()*. So we can now simply replace it with 0.

```
from __future__ import print_function
import frida
import sys

pid  = frida.spawn("testapp")
session = frida.attach(pid)
script = session.create_script("""
const testFunc2_loc = Module.findBaseAddress('testapp').add(0x11a0)
console.log("[*] testFunc2 at : " + testFunc2_loc);


Interceptor.attach(testFunc2_loc, {
    onEnter: function(args) {
      console.log("[*] retn: " + retval);
    },
    onLeave: function(retval){
      console.log("[*] Previous return value: " + retval);
      retval.replace(0);
      console.log("[*] New return value: " + retval);
    }
});
""")
script.load()
frida.resume(pid)
session.detach()
```

Run it and you should get something silimar this:
```
$ python3 testapp.py 
[*] testFunc2 at : 0x55f2499971a0
Hello, world!
test func 1 
test func 2 
Returned value is : 0 
[*] Previous return value: 0x2
[*] New return value: 0x0
```

Well done, you mananged to alter the outcome of a Linux binary. 
