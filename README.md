# Automate (Version 0.0.1 beta)
This code is code to help automate work flow by parsing up gmap files to more usable files for further automation. The goal is to make it easier to automate work flow.

This code will take a gnmap file and parse it to more useable files.

Features:
- [Parse gnmap file to readable files](#parse-gnmap-file-to-readable-files) - This will parse the gnmap file to readable files.
- [Clean up the files](#clean-up-the-files) - This will clean up the files.

# Using
There are several ways to use this code. The following are some options:

    - iL - Provide the input file.
    - h - Display the help.
    - v - Verbose mode.
    - c - Clean up the files.
```
python3 Automate.py -iL nmap-results.gnmap
```

## Parse gnmap file to readable files
The default behavor to look for a gnmap file in the current directory. After finding the file the program will parse the file and create a directory called 'nmap_results' and put the files in there.

The files that are created are:
- Hosts.txt - A list of all the hosts in the network
- Ports.txt - A list of all the ports in the network
- Services.txt - A list of all the services in the network
- TCP.txt - A list of all the TCP ports in the network
- UDP.txt - A list of all the UDP ports in the network
- all.txt - A list of all the ports in the network with the service name and port type
- HostInfo.txt - A list of all the hosts in the network with the service name and port type

Additionally, the program will create a directory called 'nmap_results/ports' and create a file for each port in the network. With the corisponding service name and port type. Within the file is a list of all the hosts that have that port open.

## Clean up the files
The program will clean up the files that are created. This will remove the files that are not needed.
```
python3 Automate.py -c
```

# Updates
- Fixed the bug that causes permission errors when running the program.
- Removed the nmap scan. (This will be added later)
- Organized the code.
