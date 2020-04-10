Idea from: https://zedt.eu/tech/linux/restarting-usb-subsystem-centos/

Add remove USB device in Kali from command line. 

Find where the device is using dmesg:
```bash
dmesg
...
[ 8983.718388] usb 2-2: new full-speed USB device number 3 using ohci-pci
[ 8984.077644] usb 2-2: New USB device found, idVendor=0483, idProduct=ffff, bcdDevice= 2.00
[ 8984.077646] usb 2-2: New USB device strings: Mfr=1, Product=2, SerialNumber=3
[ 8984.077648] usb 2-2: Product: HARDSPLOIT TOOL
[ 8984.077650] usb 2-2: Manufacturer: OPALE SECURITY
...
```
You want to complete a unbind and bind.
```bash
$ echo -n "0000:00:xx.y" > /sys/bus/pci/drivers/ohci-pci/unbind
$ echo -n "0000:00:xx.y" > /sys/bus/pci/drivers/ohci-pci/bind
```

Mine was in ohci-pci. You should see it after you complete bind again (list the devices again in the end.)
```bash
ls -la /sys/bus/pci/drivers/ohci-pci
total 0
drwxr-xr-x  2 root root    0 Apr  9 19:28 .
drwxr-xr-x 22 root root    0 Apr  9 19:25 ..
lrwxrwxrwx  1 root root    0 Apr  9 19:32 0000:00:06.0 -> ../../../../devices/pci0000:00/0000:00:06.0
--w-------  1 root root 4096 Apr  9 19:28 bind
lrwxrwxrwx  1 root root    0 Apr  9 19:26 module -> ../../../../module/ohci_pci
--w-------  1 root root 4096 Apr  9 19:26 new_id
--w-------  1 root root 4096 Apr  9 19:26 remove_id
--w-------  1 root root 4096 Apr  9 19:26 uevent
--w-------  1 root root 4096 Apr  9 19:27 unbind

$ echo -n "0000:00:06.0" > /sys/bus/pci/drivers/ohci-pci/unbind
$ echo -n "0000:00:06.0" > /sys/bus/pci/drivers/ohci-pci/bind
ls -la /sys/bus/pci/drivers/ohci-pci
$ echo -n "0000:00:06.0" > /sys/bus/pci/drivers/ohci-pci/unbind ; sleep 2; echo -n "0000:00:06.0" > /sys/bus/pci/drivers/ohci-pci/bind 
```

Also consider the following: 
https://unix.stackexchange.com/questions/91027/how-to-disable-usb-autosuspend-on-kernel-3-7-10-or-above

For Ubuntu and Debian, usbcore is compiled in the kernel, so create entries on /etc/modprobe.d will NOT work: we need to change the kernel boot parameters.

Edit the /etc/default/grub file and change the GRUB_CMDLINE_LINUX_DEFAULT line to add the usbcore.autosuspend=-1 option:
```bash
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash usbcore.autosuspend=-1"
```
Note that quit splash were already present options. So keep other options you have too.

After save the file, update grub:
```bash
sudo update-grub
```
And reboot.

Now check autosuspend value:
```bash
cat /sys/module/usbcore/parameters/autosuspend
```
And it should display -1.

In the kernel documentation is stated that someday in the future this param will change to autosuspend_delay_ms (instead of autosuspend).

