# CLONE GIT REPO ON LINUX

  ```
 git clone --recursive https://github.com/OPALESECURITY/hardsploit-gui
 cd hardsploit-gui
  ```

# INSTALLING THE GUI

* Step by step installation (Kali Linux, Debian or Uuntu & Mac Os is supported by homebrew)

  * Open a new terminal on the desktop


  * Install packages needed (ruby must be >= 2.1) with the following command:

  ```
  apt-get install ruby ruby-dev cmake libsqlite3-dev dfu-util libqt4-dev
  ```

  * Install the gems used by Hardsploit


  if you use GCC > 5.4 you need to use GCC 5.4 at least to be sure qtbindings gem can be compile without any issue, to do that (KX UPDATE 2017-08: On Kali Linux 2017, just set CC and CCX as follows/or if you are getting compilation errors with gem install below) :
  ```
  export CC=gcc
  export CXX=g++
  ```

  ```ruby
  gem install qtbindings activerecord libusb sqlite3
  ```

   Install the GUI by using the gem

   ```ruby
   gem install hardsploit_gui
   ```

   You will also need to add this line in ~/.profile file.
   ```bash
   export QT_X11_NO_MITSHM=1
   ```

   That's it ! Hardsploit is now ready to be launched. Connect your board by USB and type in the terminal

   ```
   hardsploit_gui
   ```

   At the opening you will have in the console either this message:

   ![usb-ok](images/hardsploit-connected.jpg)

   Or this one:

   ![usb-nok](/images/hardsploit-disconnected.jpg)

  If you have this last one, please check your USB connectivity. Don't forget that if you are using a virtual machine you have to attach Hardsploit to it.
  Hardsploit doesn't manage hotswap yet so you will have to
  * close the GUI
  * connect your board
  * launch the GUI again

  Hardsploit can be used without being connected but you will not have the possibility to execute commands or to use the wiring helper

For the next part [it's this way](https://github.com/OPALESECURITY/hardsploit-gui/wiki/component-management)
