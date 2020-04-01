## Install FRIDA on Linux and get up and running.

```
  pip3 install frida-tools
```

Update *~/bashrc* with the following, change <user> with your linux user account:

```
export PATH=/home/<user>/.local/bin:$PATH
```

Let's try to hack the following binary using Frida. 

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
return 1;
}
```
Compile it into an executable:
```
 gcc -o testapp testapp.c
```
**Aim:** To return something else in the function *testFunc2*.

**First** Get the offset of the function *testFunc2*. 

```
$ objdump -d testapp | grep -i "tes*"
... (removed assembly)
000000000000118d <testFunc1>:
00000000000011a0 <testFunc2>:
```

So we can clearly see that it lives at location **0x11a0**.

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
Now get the Base address for the application. We need this to calculate the actual address of the function *testFunc2*. With ASLR enbaled it will be different everytime the application runs. 

```
[Local::testapp]-> Module.findBaseAddress('testapp')                                                                           
"0x563be2666000"
```
I got my applications current Base address *0x563be2666000* and will add 0x11a0 next. 

```
[Local::testapp]-> Module.findBaseAddress('testapp').add(0x11a0)                                                               
"0x563be26671a0"
```

Pleace this into some python3 code. You can try this in the interactive element of Python3 or save it in a file frida-testapp.py.  

```
from __future__ import print_function
import frida
import sys
    
pid  = frida.spawn("testapp")
session = frida.attach(pid)

script = session.create_script("""
const func2 = Module.findBaseAddress('testapp').add(0x11a0);
send("[*] func2 at : " + func2);
console.log("[*] func2 at : " + func2);
""")

script.load()
frida.resume(pid)
session.detach()
```

The *on_message* function allows us to print something out on the console if you are not using Python3 interactive. 


```
from __future__ import print_function
import frida
import sys


def on_message(message, data):
    print(message)
    #print(message['payload'])

pid  = frida.spawn("testapp")
session = frida.attach(pid)
script = session.create_script("""
const func2 = Module.findBaseAddress('testapp').add(0x11a0)
send("[*] func2 at : " + func2);


Interceptor.attach(func2, {
    onEnter: function(args) {
    },
    onLeave: function(retval){
    retval.replace(0);
    }
});
""")
script.on("message", on_message)
script.load()
frida.resume(pid)
```



```
