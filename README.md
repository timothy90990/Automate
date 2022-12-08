# Automate (Version 0.0.5 beta)

Automate is a tool that simplifies the process of automating workflows by parsing gmap files into easily usable formats. Automate takes a gnmap file and quickly parses it into a variety of readable formats, including HTML, JSON, CSV, and XML. Automate also creates a file for each service in the network, and stores the IP addresses of all hosts that share that service in the file. This makes it easy to quickly access and work with the data from the gnmap file. Automate also includes a clean-up feature that allows you to remove any unnecessary files. 

The files that are created include:

-   Automate.html - an HTML page of the results gathered
-   open_ports:
    -   port_(tcp/udp)_(open/filterd)_service.txt - live hosts that share the same service, port, and port type
-   live_hosts.txt - an inventory of all live hosts detected in the network
-   live_ports.txt - a list of all the ports in the network
-   live_services.txt - a list of all the services in the network
-   live_tcp_ports.txt - a list of all the TCP ports in the network
-   live_udp_ports.txt - a list of all the UDP ports in the network
-   live_port_type_service.txt - a list of all the ports in the network, with the service name and port type
-   live_udp_ports.txt - a list of all the hosts in the network, with the service name and port type
-   HostInfo.json - a JSON file containing all the information gathered from the gnmap file
-   HostInfo.csv - a CSV file containing all the information gathered from the gnmap file
-   HostInfo.xml - an XML file containing all the information gathered from the gnmap file

Additionally, Automate will create a directory called 'nmap_results/ports' and create a file for each port in the network. The files will include the corresponding service name and port type, and will contain a list of all the hosts that have that port open.

## Features

-   Parse gnmap file to readable files - Automate will parse the gnmap file and create readable files.
-   Clean up the files - Automate will clean up the files that it creates, removing any files that are not needed.

## Using Automate

There are several ways to use Automate. Some options include:

-   iL - provide the input file. Default: scans the current directory for a gnmap file
-   h - display the help
-   v - verbose mode
-   vv - extra verbose mode
-   c - clean up the files
-   f - runs clean up files and then parses out the gnmap file

To use Automate, run the following command:

`python3 Automate.py`

To use Automae but specify a specific file, run the following command:

`python3 Automate.py -iL <files_name>`

To clean up the files, run the following command:

`python3 Automate.py -c`

## Examples

Here is an example of how to use Automate to parse a gnmap file and create readable files:

`python3 Automate.py`

Here is an example of how to use Automate to clean up the files that it creates:

`python3 Automate.py -c`

## Troubleshooting

If you encounter any issues when using Automate, here are some steps you can try to troubleshoot the problem:

1.  Make sure you have installed all necessary dependencies and followed any necessary configuration steps. (There shouldn't be any)
2.  Check the command line arguments you are using

Please report any issues that you are having.

# Updates
Version 0.0.6 beta
- Fixed bug where the program would fail if host is up but no ports are open
- Removed nmap parsing due to issues with nmap parsing with different versions of nmap and output formats
- Changed the HTML output to be more readable and easier to use
- Modified the parsing functions to be more reliable (hopefully)
- Changed the way the program handles the gnmap files using regex for more reliable parsing (hopefully)
- Changed the way the program handles the XML files for more reliable parsing (hopefully)

Version 0.0.5 beta
- Additional optimizations
- Changed storage type to dict
- Changed how clean function works
- Added HTML page and additional filetypes

Version 0.0.4 beta
- Fixed bug with illegal characters
- Addeed more information from gnmap file

Version 0.0.3 beta
- Optimization
- Organized the code.
- Added output file types (json,csv,xlm)
- Additional Bug fixes for flags

Version 0.0.2 beta
- Fixed the bug that causes permission errors when running the program.
- Organized the code.
- Fixed the bugs that prevented user from defining certain flags - "unkown flag"
