DAB Plus Streamer
=====================

This repository contains the implementation of an SDR DAB/DAB+ streaming server based on welle.io/welle-cli (https://www.welle.io).

Table of contents
====

  * [Supported Hardware](#supported-hardware)
  * [Building](#building)
    * [General Information](#general-information)
    * [Debian / Ubuntu Linux](#debian--ubuntu-linux)
  * [Usage](#usage)
    * [Backend options](#backend-options)
    * [Examples](#examples)

Supported Hardware
====================
The following SDR devices are supported
* Airspy R2 and Airspy Mini (http://airspy.com/)
* rtl-sdr (http://osmocom.org/projects/sdr/wiki/rtl-sdr)
* rtl_tcp (http://osmocom.org/projects/sdr/wiki/rtl-sdr#rtl_tcp)
* I/Q RAW file (https://www.welle.io/devices/rawfile)
* All SDR-devices that are supported by SoapySDR, gr-osmosdr and uhd. These are too many devices to list them all. To see if your SDR is supported, have a look at the lists at [SoapySDR](https://github.com/pothosware/SoapySDR/wiki) and [SoapyOsmo](https://github.com/pothosware/SoapyOsmo/wiki).
    * Devices supported by gr-osmosdr are supported via [SoapyOsmo](https://github.com/pothosware/SoapyOsmo/wiki)
    * Devices supported by uhd are supported via [SoapyUHD](https://github.com/pothosware/SoapyUHD/wiki)
    * One limitation is of course that the SDR devices must be tunable to the DAB+ frequencies.

### SoapySDR Notes


#### LimeSDR

Connect the antenna to the RX1_W port and configured SoapySDR antenna option to `LNAW`. `SoapySDRUtil --probe=driver=lime` may show other possible options.

#### USRP

Configured SoapySDR driver arguments option to `driver=uhd`. Configure also antenna and clock source option. To list possible values for antenna and clock source use the command `SoapySDRUtil --probe=driver=uhd`.

Building
====================

General Information
---
The following libraries and their development files are needed:
* FFTW3f
* libfaad
* librtlsdr
* libusb

Debian / Ubuntu Linux
---
This section shows how to compile DAB Plus Streamer on Debian or Ubuntu (tested with Ubuntu 22.04).

1. Install the essential packages for building software

```
sudo apt install git build-essential
```

2. Install the following packages

```
sudo apt install cmake libfaad-dev libmpg123-dev libfftw3-dev librtlsdr-dev libusb-1.0-0-dev mesa-common-dev libglu1-mesa-dev libpulse-dev libsoapysdr-dev libairspy-dev libmp3lame-dev
```

3. Clone DAB Plus Streamer

```
git clone https://github.com/nRaecheR/dab_plus_streamer
```

4. Create a build directory inside the repository and change into it

```
cd dab_plus_streamer
mkdir build
cd build
```

5. Run CMake. To enable support for RTL-SDR add the flag `-DRTLSDR=1` (requires librtlsdr) and for SoapySDR add `-DSOAPYSDR=1` (requires SoapySDR compiled with support for each desired hardware, e.g. UHD for Ettus USRP, LimeSDR, Airspy or HackRF). 

```
cmake ..
```

  or to enable support for both RTL-SDR and Soapy-SDR:

```
cmake .. -DRTLSDR=1 -DSOAPYSDR=1
```

  If you wish to use KISS FFT instead of FFTW (e.g. to compare performance), use `-DKISS_FFT=ON`.

6. Run make (or use the created project file depending on the selected generator)

```
make
```

7. Install it (as super-user)

```
make install
```

Usage
====================

Receive using RTLSDR, and tune to programme:

    dab_plus_streamer -c channel -p programme

Read an IQ file and tune to programme: (IQ file format is u8, unless the file ends with FORMAT.iq)

    dab_plus_streamer -f file -p programme

Use -D to dump FIC and all programmes to files:
 
    dab_plus_streamer -c channel -D 

Use -w to enable webserver, decode a programme on demand:
    
    dab_plus_streamer -c channel -w port -U URL

Use -Dw to enable webserver, decode all programmes:
    
    dab_plus_streamer -c channel -Dw port -U URL
    
Example: `dab_plus_streamer -c 12A -w 7979 -U http://localhost:7979` enables the webserver on channel 12A, please then go to http://localhost:7979/ where you can observe all necessary details for every service ID in the ensemble, see the slideshows, stream the audio by downloading a M3U playlist and start an external application, check spectrum, constellation, TII information and CIR peak diagramme.

Backend options
---

`-u` disable coarse corrector, for receivers who have a low frequency offset.

Use `-t [test_number]` to run a test. To understand what the tests do, please see source code.

Driver options
---

By default, `dab_plus_streamer` tries all enabled drivers in turn and uses the first device it can successfully open.

Use `-F [driver][,driver_args]` to select a specific driver and optionally pass arguments to the driver.
This allows to select the `rtl_tcp` driver (which is not autodetected) and pass the hostname or IP address and port of the rtl_tcp server to it:

    dab_plus_streamer -c 10B -p GRRIF -F rtl_tcp,192.168.12.34:1234
    dab_plus_streamer -c 10B -P GRRIF -F rtl_tcp,my.rtl-tcp.local:9876

The `rtl_sdr` driver allows the selection of the RTL-SDR USB device by specifying a serial number:

    dab_plus_streamer -c 10B -p GRRIF -F rtl_sdr,12345
    
where `12345` is the serial number of the USB device. This allows the selection of a specific USB in the case multiple devices are connected to the computer.

Examples: 
---

    dab_plus_streamer -c 10B -p GRRIF
    dab_plus_streamer -f ./ofdm.iq -p GRRIF
    dab_plus_streamer -f ./ofdm.iq -t 1

Profiling
---
If you build with cmake and add `-DPROFILING=ON`, welle-io will generate a few `.csv` files and a graphviz `.dot` file that can be used
to analyse and understand which parts of the backend use CPU resources. Use `dot -Tpdf profiling.dot > profiling.pdf` to generate a graph
visualisation. Search source code for the `PROFILE()` macro to see where the profiling marks are placed.
