# Automate (Version 0.0.3 beta)
This code is code to help automate work flow by parsing up gmap files to more usable files for further automation. The goal is to make it easier to automate work flow.

This code will take a gnmap file and parse it to more useable files.

## Parse gnmap file to readable files
The default behavor to look for a gnmap file in the current directory. After finding the file the program will parse the file and create a directory called 'nmap_results' and put the files in there.

The files that are created are:
- open_ports:
	- port_(tcp/udp)_(open/filterd)_service.txt - live hosts that share the same service,port and porttype
- live_hosts.txt - A list of all the hosts in the network
- live_ports.txt - A list of all the ports in the network
- live_services.txt - A list of all the services in the network
- live_tcp_ports.txt - A list of all the TCP ports in the network
- live_udp_ports.txt - A list of all the UDP ports in the network
- live_port_type_service.txt - A list of all the ports in the network with the service name and port type
- live_udp_ports.txt - A list of all the hosts in the network with the service name and port type
- HostInfo.json - Jason file containing all the information gathered from gnmap
- HostInfo.csv - CSV file containing all the information gathered from gnmap
- HostInfo.xml - XML file containing all the information gathered from gnmap

Additionally, the program will create a directory called 'nmap_results/ports' and create a file for each port in the network. With the corisponding service name and port type. Within the file is a list of all the hosts that have that port open.

Features:
- [Parse gnmap file to readable files](#parse-gnmap-file-to-readable-files) - This will parse the gnmap file to readable files.
- [Clean up the files](#clean-up-the-files) - This will clean up the files.

# Using
There are several ways to use this code. The following are some options:

    - iL - Provide the input file. Defualt: Scans currnt dir for gnmap file
    - h - Display the help.
    - v - Verbose mode.
    - vv - Extra verbose mode.
    - c - Clean up the files.
    - f - runs clean up files and then parses out gnmap
```
python3 Automate.py
```

## Clean up the files
The program will clean up the files that are created. This will remove the files that are not needed.
```
python3 Automate.py -c
```

# Updates
Version 0.0.3 beta
- Optimization
- Organized the code.
- Added output file types (json,csv,xlm)
- Additional Bug fixes for flags
Version 0.0.2 beta
- Fixed the bug that causes permission errors when running the program.
- Organized the code.
- Fixed the bugs that prevented user from defining certain flags - "unkown flag"