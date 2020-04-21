# Installation details for running Hardsploit on macOS

Install and update homebrew for macOS. 

Install Ruby. In this example I am showing you how to pick a version. (remove @2.6 if you want the latest version)

```bash
brew install libusb
brew install ruby@2.6
```

Once the installation is complete you will need the following lines. Keep these in a note someone for future use. You will needs these later and when ever you are running **Hardsploit**. They are needed for libusb support. 

```bash
export PATH="/usr/local/opt/ruby@2.6/bin:$PATH"
export LDFLAGS="-L/usr/local/opt/ruby@2.6/lib"
export CPPFLAGS="-I/usr/local/opt/ruby@2.6/include"
export PKG_CONFIG_PATH="/usr/local/opt/ruby@2.6/lib/pkgconfig"

ruby --version
```

Download libusb support for Ruby ([https://github.com/larskanis/libusb](https://github.com/larskanis/libusb)), build and install support. 

```
git clone https://github.com/larskanis/libusb

cd libusb/
bundle
rake -t
rake install
```

"rake install" should give you this result:

```bash
libusb 0.6.4 built to pkg/libusb-0.6.4.gem.
libusb (0.6.4) installed.
```


\* Tested on 10.14
