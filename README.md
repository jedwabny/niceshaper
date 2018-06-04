# NiceShaper

NiceShaper is the program developed for Linux router environment. It works in user space on top of standard Linux QOS implementation and iptables. By default, a proven HTB algorithm is used for the root, inner, and leaf classes, SFQ packets scheduling algorithm is the default queuing discipline (qdisc) contained within each of leaf classes, U32 and FW are used as the packets classifiers.

NiceShaper provides dynamic traffic shaping approach which is more effective than traditional shaping with static rates. While constantly monitoring the traffic flowing through the router, in response to the changing load, dynamically adjusts the rate and ceil parameters values of enabled HTB classes to the values which enable the fullest possible utilization of Internet connection throughput.

NiceShaper protects each host which uses reasonable amount of shared throughput while watching over the configured optimal utilization of Internet connection. Therefore, at the asymmetric Internet connection, takes care of download when upload is close to stop up (and vice versa). NiceShaper doesn't allow for creation of congestions, thus ensures the comfort of using interactive services as well.

# Besides of mentioned basis, NiceShaper offers:
* Clear and intuitive configuration makes the learning curve as short as possible.
* Directive called host which is a simplified class replacement sufficient for most configurations.
* Macros introduced to simplify creation of a lot of similar classes.
* Triggers which automatically change the selected class parameters at the specified hours of the day (alter trigger) or on exceeding certain amount of the transferred data (quota trigger).
* Packets marking and IMQ interfaces support is the workaround method for shaping the traffic incoming from source NATed private IP network.
* Comfortable and clear, even remotely accessible, inspection of working classes status.
* Dump of working classes status is also possible to be automatically written to a specified file every defined interval, for example in order to be web accessible.

### MRTG graph which demonstrates how NiceShaper works:

![MRTG graph](https://github.com/mjd80/niceshaper/blob/master/docs/mrtg.png)

Graph is taken from the network where too many users use upload demand P2P software, what may kills the upload throughput and finally destroys download performance as well. Using NiceShaper on the router, connected through the asymmetric xDSL line, enables the best download and upload utilization. In the same time each user can surf with the comfortable throughput available, playing online games, use interactive services, and so on. NiceShaper all the time cares of that downloading or uploading the big amount of data don't disturb the interactive. 


### Prerequisites

```
- C++ compiler from gcc package
- C and C++ standard libraries
- make utility.
```
### Installing

Unpacked package has to be compiled omitting configure step because NiceShaper is Linux only software, thus compilation procedure is simplified. 

```
$ bunzip2 niceshaper-%{version}.tar.bz2
$ tar xf niceshaper-%{version}.tar
$ cd niceshaper-%{version}
$ make
$ su
# make install 
```

Make install command creates all needed directories (/etc/niceshaper, /var/lib/niceshaper, and /usr/share/doc/niceshaper). It copies the compiled binary to the /usr/local/bin directory. Example configuration files are copied to the /etc/niceshaper directory.
