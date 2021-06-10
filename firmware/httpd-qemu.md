# Test run of ARM httpd using QEMU

## Using QEMU to check ARM-based httpd in Ubuntu 20.04

**Aim:** Run an ARM-based httpd binary and connect to it in x86_64 Linux.

**Result:** Learnt how to run the app. using QEMU and how to debug it, since it was having issues progressing due to files missing and execution would halt. I didn't manage to connect to it, since the application is now waiting for some input from the socket it is connecting to (more work is needed reversing it -in short-). I should also point out the I had issues running it with Qiling Framework (Version 1.2.3) due to shared libraries not loading correctly. This needs further investigation as well. 

Linux system used Ubuntu 20.04:

```bash
# uname -a
Linux test-r 5.8.0-53-generic #60~20.04.1-Ubuntu SMP Thu May 6 00:52:46 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

I have a httpd that I have extracted from an embedded system running on ARM SoC. I wanted to test it and see if I could get the webserver up and running. 

TL;DR: I could not, I got up to a point and it is stuck in a timed loop. It is waiting for something (I have to figure that one out at some point). 

For now I will document how I got it running and tracing some of the functions using only QEMU and GDB. 

What you will need:

* qemu-static-arm

* gdb-multiarch

```bash
$  sudo apt install gdb-multiarch qemu-static-arm
```

Extract the target binary/ies and all libraries. Maybe look at copying /etc as well. Assume we have everything in ```/home/test/testsystem/```, with binaries in ```/home/test/testsystem/bin``` and libraries in ```/home/test/testsystem/lib```. 

**Hint:** Something I did try out was manipulate the binaries with a hex editor and have them use ```/vap``` instead of ```/var```, hex ```70``` instead of ```72```. This made testing and setting permissions much easier as well. This technique is not shown here. 

You will need two terminal windows for this run. 

To run the application using QEMU I used the following command and options (first terminal window):

```bash
$ qemu-arm-static -g 9999 -L /home/test/testsystem/ -strace ./bin/httpd
```

1. ```-g 9999``` will start qemu and then wait for gdb to connect before continuing execution. (remove it if you don't want the gdb option)
2. ```-L /home/test/testsystem/``` is the path to the base folder with our arm-based lib files cane be found (remember most applications will have the lib folder included e.g. /lib/libc.6.so) 
3. ```-strace``` is used to provide us with a trace of all the system calls and arguments. 

**Hint:** In my case, CTRL+C would only be caught and the app would carry on running. Therefore, with GDB attached the application's execution could easily be stopped and inspected. 

Connecting using GDB (in a second terminal):

```bash
$ gdb-multiarch 
(gdb) target remote 127.0.0.1:9999

(gdb) c
Continuing.

```

The application is now producing lots of the same text. Mainly that a file is not found. You will notice in the trace it is providing the address pointer in the function connect(). You can google and see what the arguments are, this is how I know that it is the address I am after. So I use CTRL+C to stop the execution and check out the memory address.  

```bash
[qemu]
...
1710827 connect(556,0xffeb5ec4,110) = -1 errno=2 (No such file or directory)
...
```
Back to GDB and it is simple as ```x/8s 0xffeb5ec4``` and the address. The command here is saying examine the memory address we want it 8 times and it is a string. 

```bash
[gdb]
...
Program received signal SIGINT, Interrupt.
0xfeec640c in ?? ()
(gdb) x/8s 0xffeb5ec4
0xffeb5ec4:	"\001"
0xffeb5ec6:	"/var/run/socket-temp"
0xffeb5ee6:	""
0xffeb5ee7:	""
0xffeb5ee8:	""
0xffeb5ee9:	""
0xffeb5eea:	""
0xffeb5eeb:	""
```

So it is trying to access this socket. Let's try to emulate one and see what happens. 

The following python3 code (not mine) will setup a local socket listening on ```/var/run/socket-temp``` and port ```0.0.0.0:8080``` :

```python
# Code from : https://stackoverflow.com/questions/22624653/create-a-virtual-serial-port-connection-over-tcp
#!/usr/bin/python

import socket
import sys
import serial

#open serial port
ser = serial.Serial('/var/run/socket-temp', 115200, timeout=0)
#create socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

#bond to the port. Don't use localhost to accept external connections
server_address = ('', 8080)
print('starting up on {} port {}'.format(*server_address))
sock.bind(server_address)

#listen
sock.listen(1)

#loop
while True:
    #waits for a new connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        print('connection from', client_address)
        #continously send from serial port to tcp and viceversa
        connection.settimeout(0.1)
        while True:
            try:
                data = connection.recv(16)
                if data == '': break
                ser.write(data)
            except KeyboardInterrupt:
                connection.close()
                sys.exit()
            except Exception as e:
                pass
            received_data = ser.read(ser.inWaiting())
            connection.sendall(received_data)
    except Exception as e:
        print(e)

    finally:
        #clean up connection
        connection.close()


```

As I mentioned before I didn't get much further than this as now the application is stuck in an infinite loop waiting for some kind of input from the socket to continue it's operation. 
 
The idea is to document what I did and how I got to the point of executing the ARM binary on a x86_64 Linux system for easy debugging.