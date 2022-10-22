r""" This program takes nmap output file .gnmap and parses it for open ports
The functions:
    nmap_parser: Parses the nmap output file and creates a directory for the results
    options: Gets the options from the command line
    main: Runs the program
Output:
    nmap_results: Directory with the results
By: Timothy Stowe
Date: 6/4/2022
"""

import logging
import os
import sys


#
# Version of python the script is running on
#
PYTHON_VERSION = sys.version_info[0]
#
# Author of this script: Timothy Stowe
#
AUTHOR = "Timothy Stowe"

#
# Current version of Automate.py
#
VERSION = "0.0.1"

#
# Save Directory
#
SAVEDIRPORTS = "nmap_results/open_ports"
SAVEDIR = "nmap_results"

#
# Files
#
LOGFILE = 'Automate.log'
INPUTFILE = ""


# ------------------------------------------------------------------------------
# Start of logging section
# ------------------------------------------------------------------------------


consoleFormatter = logging.Formatter(
    '%(message)s')
logging.basicConfig(filename=LOGFILE, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(lineno)d %(message)s')

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(consoleFormatter)
consoleHandler.setLevel(logging.ERROR)
logging.getLogger().addHandler(consoleHandler)

# ------------------------------------------------------------------------------
# HostInfo Class
# ------------------------------------------------------------------------------


class HostInfo:
    def __init__(self):
        self.host = []
        self.ports = []
        self.portsPlusType = []
        self.services = []
        self.all = []
        self.udp = []
        self.tcp = []

    def update(self):
        for slist in self.portsPlusType:
            for item in slist:
                if "tcp" in item:
                    z = item.split("/")[0]
                    self.tcp.append(z)
                if "udp" in item:
                    z = item.split("/")[0]
                    self.udp.append(z)
        self.tcp = list(set(self.tcp))
        self.udp = list(set(self.udp))

    def saveHostInfo(self):
        with open(SAVEDIR + "/" + "HostInfo.txt", "a") as f:
            for host in self.host:
                f.write("Host: " + host + "\n")
                f.write(
                    "Ports: " + ", ".join(self.all[self.host.index(host)]) + "\n")
                f.write("\n")

    def getSublist(self, LargeList):
        lst = []
        for smallList in LargeList:
            for item in smallList:
                lst.append(item)
        return list(set(lst))

    def savePortsToFile(self):
        all = self.getSublist(self.all)
        for service in all:
            sameService = []
            for host in self.host:
                for serviceOnHost in self.all[self.host.index(host)]:
                    if service == serviceOnHost:
                        sameService.append(host)
            port = service.split("/")[0]
            portType = service.split("/")[1]
            service = service.split("/")[2]
            with open(SAVEDIRPORTS+"/%s_%s_%s.txt" %
                      (port, portType, service), "a") as f:
                for host in sameService:
                    f.write("%s\n" % host)

#
# Color formatting
#


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ------------------------------------------------------------------------------
# Start of nmap command section
# Here we will start all the commands to parse out nmap results
# ------------------------------------------------------------------------------


class nmapParse:
    def nmap_parser():
        lst = []
        try:
            logging.info("Opening %s and parsing results" % flags.inputFile)
            # Open up the nmap results file
            with open(flags.inputFile, "r") as f:
                for line in f:
                    if "nmap" in line:
                        continue
                    elif "open" in line:
                        lst.append(line)
            logging.info("Creating a directory for the results")
            os.mkdir("nmap_results")
            os.mkdir(SAVEDIRPORTS)
        except FileNotFoundError as e:
            logging.error(e)
            sys.exit(1)
        except OSError as e:
            logging.critical(e)
            sys.exit(1)

        logging.info("Parsing Nmap results")
        # Here we are creating a file for each port and writting the ip
        # to the port file

        for line in lst:
            if "open" not in line:
                continue
            line = line.split()
            ip_address = line[1]
            portList, portPlusTypeList, servicesList, allList = [], [], [], []
            # Here we are creating a file for each port and writting the ip
            # to the port file
            for x in line:
                # Loops through the line and checks to see if it is a port
                # and if the port is open ignoring filtered ports
                if "open" in x:
                    # Get the port number
                    port = x.split("/")[0]
                    portType = x.split("/")[2]
                    service = x.split("/")[4]
                    if service == "":
                        service = "unknown"
                    p = port + "/" + portType
                    a = port + "/" + portType + "/" + service
                    portList.append(port)
                    portPlusTypeList.append(p)
                    servicesList.append(service)
                    allList.append(a)
            HostInfo.host.append(ip_address)
            HostInfo.ports.append(portList)
            HostInfo.portsPlusType.append(portPlusTypeList)
            HostInfo.services.append(servicesList)
            HostInfo.all.append(allList)
        HostInfo.update()
        logging.info("Finished parsing Nmap results")

    def saveToFile():
        logging.info("Creating files")
        HostInfo.savePortsToFile()
        logging.info("Getting Sublists")
        services = HostInfo.getSublist(HostInfo.services)
        ports = HostInfo.getSublist(HostInfo.ports)
        all = HostInfo.getSublist(HostInfo.all)
        logging.info("Removing duplicates")
        hosts = list(set(HostInfo.host))

        tcp = HostInfo.tcp
        udp = HostInfo.udp

        logging.info("Creating a file for each port, host, and service")
        files = ["services.txt", "ports.txt",
                 "hosts.txt", "all.txt", "tcp.txt", "udp.txt"]
        data = [services, ports, hosts, all,
                tcp,  udp]
        for x in range(len(files)):
            with open(SAVEDIR + "/%s" % (files[x]), "a") as f:
                [f.write("%s\n" % x) for x in data[x]]

        HostInfo.saveHostInfo()
        logging.info("All Files Created")
        logging.debug("Totals hosts: %s Services: %s udp: %s tcp: %s" % (
            len(hosts), len(services), len(udp), len(tcp)))
        logging.info("Total hosts found: %s" % len(hosts))
        logging.info("Total services and ports found: %s" % len(ports))
        logging.info("Total udp ports found: %s" % len(udp))
        logging.info("Total tcp ports found: %s" % len(tcp))

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------


class flags:
    """
    -h  --help                        Displays the help screen
    -i  -iL  --input  --input-list    Input file from nmap scanner (.gnmap)
                                      Default: looks for .gnmap in current directory
    -f  --force                       Force the program to run by deleteing nmap_results folder
                                      Default: Exit if the directory already exists
    -c  --clean                       Clean the results directory by deleteing nmap_results folder
                                      Default: Just parse the file
    -n                                Silent Mode doesnt display header
    -v                                Verbose output
    -vv --verbose                     Extra Verbose output
    """

    def __init__(self, argv=sys.argv):
        self.header = True
        self.help = False
        self.scanner = False
        self.force = False
        self.verbose = False
        self.clean = False
        self.inputFile = False
        for i in range(1, len(argv)):
            if argv[i] in ("-h", "--help"):
                self.help = True
                break
            elif argv[i] in ("-iL", "--input-list", "-i", "--input"):
                self.inputFile = True
                INPUTFILE = argv[i + 1]
            elif argv[i] in ("--force", "-f"):
                self.force = True
            elif argv[i] in ("--clean", "-c"):
                self.clean = True
            elif argv[i] in ("--verbose", "-vv"):
                consoleHandler.setLevel(logging.DEBUG)
            elif argv[i] in "-v":
                consoleHandler.setLevel(logging.INFO)
            elif argv[i] in "-n":
                self.header = False
# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------


def main():
    if flags.help:
        helpScreen()
        sys.exit(1)
    if flags.clean or flags.force:
        # Check to see if we have enough permissions to delete the files
        # if we don't have permissions we will exit
        logging.info("Checking to see if we have permissions to delete files")
        try:
            logging.info("Removing %s" % SAVEDIR)
            if os.path.exists(SAVEDIRPORTS):
                [os.remove(SAVEDIRPORTS + "/" + x)
                 for x in os.listdir(SAVEDIRPORTS)]
                os.rmdir(SAVEDIRPORTS)
            if os.path.exists(SAVEDIR):
                [os.remove(SAVEDIR + "/" + x)
                 for x in os.listdir(SAVEDIR)]
                os.rmdir(SAVEDIR)
            if flags.clean:
                # Close the log file
                logging.info("Closing log file")
                logging.shutdown()
                os.remove(LOGFILE)
                print("All files removed")
                sys.exit(0)
        except OSError as e:
            logging.critical(e)
            sys.exit(1)

    # If user did not provide an input file
    # Skips if the user wants help
    if flags.inputFile is not False or INPUTFILE is not None:
        # look in current directory for a .gnmap
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        for f in files:
            # If it is a .gnmap file
            if f.endswith(".gnmap"):
                flags.inputFile = f
                break
        if flags.inputFile == "":
            logging.critical("No input file provided, exiting")
            helpScreen()
            sys.exit(1)
        else:
            logging.info("No input file provided, using %s" % flags.inputFile)
    # If user wants help or failed to provide an input file and we couldnt find one
    nmapParse.nmap_parser()
    nmapParse.saveToFile()
    print("Finished parsing files created check %s directory" % SAVEDIR)


def helpScreen():
    print("Usage: python3 Automate.py -iL <inputfile>")
    # Print each flags help __doc__
    print("\nFlags:")
    print(flags.__doc__)
    print("\nExamples:")
    print("\tpython3 Automate.py -iL input.gnmap")
    sys.exit(0)


# ------------------------------------------------------------------------------
# Start of header section
# ------------------------------------------------------------------------------


def header():
    """
    #####################################################################
     _______ __   __ _______ _______ __   __ _______ _______ _______
    |   _   |  | |  |       |       |  |_|  |   _   |       |       |
    |  |_|  |  | |  |_     _|   _   |       |  |_|  |_     _|    ___|
    |       |  |_|  | |   | |  | |  |       |       | |   | |   |___
    |       |       | |   | |  |_|  |       |       | |   | |    ___|
    |   _   |       | |   | |       | ||_|| |   _   | |   | |   |___
    |__| |__|_______| |___| |_______|_|   |_|__| |__| |___| |_______|
    Version: {0}                                By: {1}
    #####################################################################
    """
    logging.info("Starting Automate.py version %s" % VERSION)
    if flags.header is not True:
        return
    print(bcolors.OKGREEN+header.__doc__.format(VERSION, AUTHOR)+bcolors.ENDC)
    print("Python Version % s" % PYTHON_VERSION)
    print("This program is used to take a gnmap file and parse for easier automation")


###############################################################################
if __name__ == "__main__":
    HostInfo = HostInfo()
    flags = flags()
    header()
    main()