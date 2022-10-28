r""" This program takes nmap output file .gnmap and parses it for open ports
The functions:
    nmap_parser: Parses the nmap output file and creates a directory for the results
    options: Gets the options from the command line
    main: Runs the program
Output:
    SAVEDIR: Directory with the results
    SAVEDIRPORTS: Directory with the open ports
    LOGFILE: Log
By: Timothy Stowe
Date: 10/25/2022
($port, $state, $protocol, $owner, $service, $rpc_info, $version)
"""

import logging
import os
import random
import sys
import time

# ------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------
PYTHON_VERSION = sys.version_info[0]
AUTHOR = "Timothy Stowe"
VERSION = "0.0.3"
SAVEDIR = "nmap_results"  # Cange Savedir to the directory you want to save the results
SAVEDIRPORTS = SAVEDIR + "/open_ports"
LOGFILE = "Automate.log"
INPUTFILE = ""  # Leave blank unless you want to specify before running
# python -m auto_py_to_exe

# ------------------------------------------------------------------------------
# Colors formatting
# ------------------------------------------------------------------------------
class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLDRED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    WARNING = "\033[93m"


# ------------------------------------------------------------------------------
# Start of logging section
# ------------------------------------------------------------------------------
class CustomFormatter(logging.Formatter):
    format = "%(levelname)s: %(message)s"

    FORMATS = {
        logging.DEBUG: bcolors.GREY + format + bcolors.RESET,
        logging.INFO: bcolors.GREY + format + bcolors.RESET,
        logging.WARNING: bcolors.YELLOW + format + bcolors.RESET,
        logging.ERROR: bcolors.RESET + bcolors.RED + format + bcolors.RESET,
        logging.CRITICAL: bcolors.BOLDRED + format + bcolors.RESET,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


consoleFormatter = logging.Formatter("%(message)s")
logging.basicConfig(
    filename=LOGFILE,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(lineno)d %(message)s",
)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(CustomFormatter())
consoleHandler.setLevel(logging.ERROR)
logging.getLogger().addHandler(consoleHandler)

# ------------------------------------------------------------------------------
# HostInfo Class
# ------------------------------------------------------------------------------
class HostInfo:
    def __init__(self):
        self.inputFile = INPUTFILE
        self.hostDict = {}
        self.allServicesList = []
        self.numbTcp = 0
        self.numbUdp = 0
        self.infilelines = []

    def setservices(self) -> None:
        allServicesS = []
        allServices = []
        for host in self.hostDict:
            for service in self.hostDict[host]:
                all = "/".join(service)
                if all not in allServicesS:
                    allServicesS.append(all)
                    allServices.append(service)
        self.allServicesList = allServices
        self.setnumbs()

    def setnumbs(self) -> None:
        for allServ in HostInfo.allServicesList:
            if "tcp" in allServ[2]:
                self.numbTcp += 1
            if "udp" in allServ[2]:
                self.numbUdp += 1


# ------------------------------------------------------------------------------
# Files Class
# ------------------------------------------------------------------------------
class Files:
    """
    Files Class where all the files are made
    """

    def create_dir() -> None:
        logging.info("Creating %s directory" % SAVEDIR)
        # elif: Check to see if the directory is empty
        if not os.path.exists(SAVEDIR):
            os.makedirs(SAVEDIR)
        elif os.listdir(SAVEDIR):
            logging.critical("Directory %s is not empty" % SAVEDIR)
            sys.exit(1)
        if not os.path.exists(SAVEDIRPORTS):
            os.makedirs(SAVEDIRPORTS)
        elif os.listdir(SAVEDIRPORTS):
            logging.critical("Directory %s is not empty" ^ SAVEDIRPORTS)
            sys.exit(1)

    def save_results_file() -> None:
        services, ports, all, hosts, tcp, udp = [], [], [], [], [], []
        logging.debug("Getting Sublists")
        for allServ in HostInfo.allServicesList:
            services.append(allServ[4])
            ports.append(allServ[0])
            all.append("/".join(allServ))
            if "tcp" in allServ[2]:
                tcp.append(allServ[0])
            if "udp" in allServ[2]:
                udp.append(allServ[0])
        for host in HostInfo.hostDict:
            hosts.append(host)

        data = {
            "live_services": services,
            "live_ports": ports,
            "live_hosts": hosts,
            "live_port_type_service": all,
            "live_tcp_ports": tcp,
            "live_udp_ports": udp,
        }
        files = []
        logging.debug("Saving Files")
        for ftype in data:
            with open(SAVEDIR + "/" + ftype + ".txt", "a") as f:
                f.write("\n".join(data[ftype]))
                files.append(ftype + ".txt")

        logging.debug("Files created: %s" % ", ".join(files))

    def writehosts() -> None:
        with open(SAVEDIR + "/" + "HostInfo.txt", "a") as f:

            # get total number of hosts
            f.write("#Total Hosts: %s\n" % len(HostInfo.hostDict))
            f.write("#Total Services: %s\n" % len(HostInfo.allServicesList))
            f.write("#Total TCP Services: %s\n" % HostInfo.numbTcp)
            f.write("#Total UDP Services: %s\n\n" % HostInfo.numbUdp)

            for host in HostInfo.hostDict:
                f.write("Host: " + host + "\n")
                tempList = []
                for all in HostInfo.hostDict[host]:
                    all = "/".join(all)
                    tempList.append(all)
                f.write("Ports: " + ", ".join(tempList) + "\n")
                f.write("\n")
            logging.debug("Files created: %s" % "HostInfo.txt")

    def save_ports_file() -> None:
        # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
        logging.info("Creating files in " + SAVEDIRPORTS)
        files = []
        for service in HostInfo.allServicesList:
            file = "%s_%s_%s_%s.txt" % (
                service[0],
                service[1],
                service[2],
                service[4],
            )
            files.append(file)
            with open(SAVEDIRPORTS + "/" + file, "a") as f:
                for host in HostInfo.hostDict:
                    if service in HostInfo.hostDict[host]:
                        f.write("%s\n" % host)
        logging.debug("Files created: %s" % ", ".join(files))

    def save_json() -> None:
        import json

        with open(SAVEDIR + "/" + "HostInfo.json", "w") as f:
            json.dump(HostInfo.hostDict, f, indent=4)
        logging.debug("Files created: %s" % "HostInfo.json")

    def save_csv() -> None:
        import csv

        with open(SAVEDIR + "/" + "HostInfo.csv", "w") as f:
            writer = csv.writer(f)
            # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
            writer.writerow(
                ["Host", "Port", "Protocol", "Owner", "Service", "RPC Info", "Version"]
            )
            for host in HostInfo.hostDict:
                for service in HostInfo.hostDict[host]:
                    writer.writerow(
                        [
                            host,
                            service[0],
                            service[1],
                            service[2],
                            service[3],
                            service[4],
                            service[5],
                            service[6],
                        ]
                    )
        logging.debug("Files created: %s" % "HostInfo.csv")

    def save_xml() -> None:
        # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
        import xml.etree.ElementTree as ET

        root = ET.Element("HostInfo")
        for host in HostInfo.hostDict:
            hostElement = ET.SubElement(root, "Host")
            hostElement.set("name", host)
            for service in HostInfo.hostDict[host]:
                serviceElement = ET.SubElement(hostElement, "Service")
                serviceElement.set("version", service[6])
                serviceElement.set("rpc_info", service[5])
                serviceElement.set("owner", service[3])
                serviceElement.set("service", service[4])
                serviceElement.set("state", service[1])
                serviceElement.set("protocol", service[2])
                serviceElement.set("port", service[0])
        tree = ET.ElementTree(root)
        tree.write(SAVEDIR + "/" + "HostInfo.xml")
        logging.debug("Files created: %s" % "HostInfo.xml")

    def save_sql3() -> None:
        import sqlite3

        conn = sqlite3.connect(SAVEDIR + "/" + "HostInfo.db")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE HostInfo (host text, port text, state text, protocol text, service text)"
        )
        for host in HostInfo.hostDict:
            for service in HostInfo.hostDict[host]:
                c.execute(
                    "INSERT INTO HostInfo VALUES (?,?,?,?,?,?,?)",
                    (
                        host,
                        service[0],
                        service[1],
                        service[2],
                        service[3],
                        service[4],
                        service[5],
                        service[7],
                    ),
                )
        conn.commit()
        conn.close()
        logging.debug("Files created: %s" % "HostInfo.db")


# ------------------------------------------------------------------------------
# Nmap Parser Class
# ------------------------------------------------------------------------------
class NmapParse:
    def nmap_parser() -> None:
        try:
            logging.info("Opening %s and extracting lines" % HostInfo.inputFile)
            with open(HostInfo.inputFile, "r") as f:
                for line in f:
                    if line[0] == "#":
                        continue
                    elif "Ports:" in line:
                        HostInfo.infilelines.append(line)
        except FileNotFoundError as e:
            logging.critical(e)
            sys.exit(1)
        except OSError as e:
            logging.critical(e)
            sys.exit(1)

        logging.info("Parsing Nmap file")
        for line in HostInfo.infilelines:
            NmapParse.extractor(line)
        logging.info("Finished parsing Nmap file")

    def extractor(line: str) -> None:
        line = line.split()
        ip_address = line[1]
        allList = []
        line = line[4:-4]
        line = "".join(line)
        line = line.split(",")
        for ports_r in line:
            ports = NmapParse.ports_list(ports_r)
            allList.append(ports)
        HostInfo.hostDict.update({ip_address: allList})
        HostInfo.setservices()

    def ports_list(ports_r: list) -> list:
        # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
        invalid_chars = "\<>:|?*;=!^"
        for char in invalid_chars:
            if char in ports_r:
                logging.debug("Invalid character %s found in: %s" % (char, ports_r))
                ports_r = ports_r.replace(char, "_")
        ports = ports_r.split("/")
        return ports


# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------
class Flag:
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
        self.inputFlag = False
        self.get_user_args()

    def get_user_args(self):
        avaliableFlags = [
            "-h",
            "--help",
            "-i",
            "-iL",
            "--input",
            "--input-list",
            "-f",
            "--force",
            "-c",
            "--clean",
            "-n",
            "-v",
            "-vv",
            "--verbose",
        ]
        inputList = ["-i", "-iL", "--input", "--input-list"]
        # Get the user arguments
        for i, arg in enumerate(sys.argv):
            if i == 0:
                continue
            # Check to see if "-" is the first character
            if arg[0] == "-" and arg in avaliableFlags:
                if arg in ["-h", "--help"]:
                    self.help = True
                    break
                elif arg in ["-i", "-iL", "--input", "--input-list"]:
                    if self.inputFlag:
                        logging.error("Only one input file can be used")
                        self.help = True
                        break
                    if (i + 1 >= len(sys.argv)) or sys.argv[i + 1] in avaliableFlags:
                        logging.error("No input file specified after %s" % arg)
                        self.help = True
                        break
                    elif not os.path.isfile(sys.argv[i + 1]):
                        logging.error(
                            "File %s does not exist" % sys.argv[i + 1]
                            + "\n"
                            + "Please enter a valid file or leave blank to use the default\n"
                            + ".gnmap file in the current directory\n"
                        )
                        self.help = True
                        break
                    else:
                        self.inputFlag = True
                        HostInfo.inputFile = sys.argv[i + 1]
                elif arg in ["-f", "--force"]:
                    self.force = True
                elif arg in ["-c", "--clean"]:
                    self.clean = True
                elif arg in ["-n"]:
                    self.header = False
                elif arg in ["-v"]:
                    consoleHandler.setLevel(logging.INFO)
                elif arg in ["-vv", "--verbose"]:
                    consoleHandler.setLevel(logging.DEBUG)
            elif self.inputFlag and sys.argv[i - 1] in inputList:
                continue
            else:
                logging.error("Invalid argument: %s" % arg)
                self.help = True
                break


# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------
def main() -> None:
    if Flag.help:
        help_screen()
        sys.exit(1)
    if Flag.clean or Flag.force:
        logging.info("Trying to delete files")
        try:
            logging.info("Removing %s" % SAVEDIR)
            if os.path.exists(SAVEDIRPORTS):
                [os.remove(SAVEDIRPORTS + "/" + x) for x in os.listdir(SAVEDIRPORTS)]
                os.rmdir(SAVEDIRPORTS)
            if os.path.exists(SAVEDIR):
                [os.remove(SAVEDIR + "/" + x) for x in os.listdir(SAVEDIR)]
                os.rmdir(SAVEDIR)
            if Flag.clean:
                logging.info("Closing log file")
                logging.shutdown()
                os.remove(LOGFILE)
                print("All files removed")
                sys.exit(0)
        except OSError as e:
            logging.critical(e)
            sys.exit(1)
    if Flag.inputFlag == False and HostInfo.inputFile == "":
        # look in current directory for a .gnmap
        files = [f for f in os.listdir(".") if os.path.isfile(f)]
        for f in files:
            # If it is a .gnmap file
            if f.endswith(".gnmap"):
                HostInfo.inputFile = f
                break
        if HostInfo.inputFile == "":
            logging.critical("No input file provided or found, exiting")
            help_screen()
            sys.exit(1)
        else:
            logging.info("No input file provided, using %s" % HostInfo.inputFile)

    # Start parsing the file
    NmapParse.nmap_parser()

    # File Saving
    Files.create_dir()
    Files.save_ports_file()
    Files.writehosts()
    Files.save_results_file()
    Files.save_json()
    Files.save_csv()
    Files.save_xml()
    # Files.save_sql3()

    # Finish
    print("Finished parsing, files created check %s directory" % SAVEDIR)


# ------------------------------------------------------------------------------
# Help Screen
# ------------------------------------------------------------------------------
def help_screen() -> None:
    print("Usage: python3 Automate.py -iL <inputfile>")
    print("\nFlags:")
    print(Flag.__doc__)
    print("\nExamples:")
    print("\tpython3 Automate.py -iL input.gnmap")
    sys.exit(0)


# ------------------------------------------------------------------------------
# Start of header section :TS
# ------------------------------------------------------------------------------
def header() -> None:
    """
    {2}#####################################################################
     _______ __   __ _______ _______ __   __ _______ _______ _______
    |   _   |  | |  |       |       |  |_|  |   _   |       |       |
    |  |_|  |  | |  |_     _|   _   |       |  |_|  |_     _|    ___|
    |       |  |_|  | |   | |  | |  |       |       | |   | |   |___
    |       |       | |   | |  |_|  |       |       | |   | |    ___|
    |   _   |       | |   | |       | ||_|| |   _   | |   | |   |___
    |__| |__|_______| |___| |_______|_|   |_|__| |__| |___| |_______|
    Version: {0}                                By: {1}
    #####################################################################{3}
    """
    logging.info("Starting Automate.py version %s" % VERSION)
    if Flag.header is not True:
        return
    colors = [
        bcolors.OKBLUE,
        bcolors.OKCYAN,
        bcolors.OKGREEN,
        bcolors.YELLOW,
        bcolors.RED,
        bcolors.GREY,
    ]
    color = random.choice(colors)
    print(header.__doc__.format(VERSION, AUTHOR, color, bcolors.RESET))
    print("Python Version % s" % PYTHON_VERSION)
    print("This program is used to take a gnmap file and parse for easier automation")


###############################################################################
if __name__ == "__main__":
    start_time = time.time()
    HostInfo = HostInfo()
    Flag = Flag()
    header()
    main()
    logging.info("Finished in %s seconds" % (time.time() - start_time))
