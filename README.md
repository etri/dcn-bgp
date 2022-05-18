NDN is a future internet architecture for the purpose of efficent search and distribution of information by using data name instead of existing IP addresses.   
Since NDN basically has an abstract concept for packet routing and forwarding, 
it is necessary to propagate the routing information about name based prefixes of data.
 
NDN-BGP is free software that manages BGP routing protocol on NDN Networking.

The goal of NDN-BGP is to support the scalability. Basically, NDN should delivery all the data on the network by only utilizing their names.  
However, There are countless amounts of data on the Internet to be accomodated all of their names by NDN-BGP.
In order to solve this problem, we propose the use of network name separated from data name to route unknown networks. 

NDN-BGP is designed and build based on IP-Based BGP Routing Protocol, which is a inter-domain routing protocol of the current Internet.  
Below figure shows the high-level interaction of the NDN-BGP with MW-NFD and other applications.  
<img src="/images/bgp.GIF" width="50%" height="%40">

Because NDN-BGP is built based on BGP, it follows the message formats and attributes of the protocol.  
Our design to build NDN-BGP is to simply transform IP addresses into network names for the reachability information.  
Following this design, we find BGP’s messages and attributes that use IP addresses in their field.  
Of those, OPEN, KEEPALIVE and UPDATE messages and NEXT-HOP attributes are required to replace the IP addresses with network names of domains.
<img src="/images/messages.GIF" width="60%" height="%40">  
Above figure shows the Messages that were modified to repace IP address.  

We also modified NDN-CXX library to enable RIB Manager to support the origin of the route from NDN-BGP.  

# Prerequisties

* NFD and its dependencies

Refer to Getting started with NFD(https://named-data.net/doc/NFD/current/INSTALL.htm) for detailed installation and running instruction.

# NDN-BGP Installation Instructions

The file 'configure.ac' (or 'configure.in') is used to create 'configure' by a program called 'autoconf'.  
You need 'configure.ac' if you want to change it or regenerate 'configure' using a newer version of 'autoconf'.  
The simplest way to compile this package is:  
   1. 'cd' to the directory containing the package's source code and type './booststrap.sh' to configure the package for your system.  
   2. type './configure CC=g++' to configure the package for your system.  
      Running 'configure' might take a while.  While running, it prints some messages telling which features it is checking for.  
   3. Type 'make' to compile the package.  
   4. Type 'make install' to install the programs and any data files and documentation.  
      When installing into a prefix owned by root, it is recommended that the package be configured and built as a regular  
      user, and only the 'make install' phase executed with root privileges.  

# Running

$ cd /usr/local/etc  
$ sudo cp dbgpd.conf.sample dbgpd.conf  
$ sudo cp dbgpd-static.conf.sample dbgpd-static.conf  


$ mkdir -p /tmp/dbgp  
$ dbgp

# Testing NDN-BGP  
Please refer to [topology](example_topology.md)

## Releases

NDN-BGP version is set to same as the base BGP routing protocol on Quagga.

### NDN-BGP 0.7.1   (Nov. 19, 2021)
  - Based on NFD 0.7.1 & ndn-cxx 0.7.1
  - Added Features :  
      * E-BGP/I-BGP  
      * Route Reflector  
      * Redistribution from Static  
        
   - Not Supported Yet :  
      * Confederation    
      * Network Name Aggregation
      * Mac OS Platform  
      
 ## Credits
 NDN-BGP is designed and developed by:

 - Sung Hyuk Byun (shbyun@etri.re.kr)
 - Jong Seok Lee (viper@etri.re.kr)


 This work is one of research results of the project "Hyper-connected Intelligent Infrastructure Technology
 Development" conducted by ETRI, Korea. The  project leaders are:

 - Namseok Ko (nsko@etri.re.kr)
 - Sun Me Kim (kimsunme@etri.re.kr)
