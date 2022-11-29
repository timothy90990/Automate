r""" This program takes nmap output file .gnmap and parses it for open ports
The functions:
    nmap_parser: Parses the nmap output file and creates a directory for the results
    options: Gets the options from the command line
    main: Runs the program
Output:
    HostInfo.saveDir: Directory with the results
    HostInfo.saveDirPorts: Directory with the open ports
    LOGFILE: Log
By: Timothy Stowe
Date: 11/27/2022
"""

import logging
import os
import random
import shutil
import sys
import time


# ------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------
PYTHON_VERSION = sys.version_info[0]
AUTHOR = "Timothy Stowe"
VERSION = "0.0.6"
LOGFILE = "Automate.log"
INPUTFILE = ""  # Leave blank unless you want to specify before running
SUPPORTEDFILES = ["xml", "gnmap"]
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
        self.all_service_list = []  # [{}, {}, {}]
        self.host_dict = {}
        # host_dict["host"][0,1,2]["port"]
        self.numPors = {"tcp": 0, "udp": 0}
        self.saveDir = "nmap_results"
        self.saveDirPorts = self.saveDir + "/open_ports"

    def update_host(self, update=None, os=None) -> None:
        # update = {"host": [{"port": 80, "state": "open", "protocol": "tcp", "owner": "root", "service": "http"}]}
        if update:
            logging.debug("updating self.host_dict with: %s", update)
            self.host_dict.update(update)
        if os:
            logging.debug("Found Os: %s", os)
            pass
        host = list(update.keys())[0]
        for service in update[host]:
            self.__setnumbs(service)
            self.__setservice(service)

    def __setservice(self, service) -> None:
        __temp_dict = {
            "port": service.get("port"),
            "state": service.get("state"),
            "protocol": service.get("protocol"),
            "service": service.get("service"),
            "version": service.get("version"),
        }
        if __temp_dict not in self.all_service_list:
            self.all_service_list.append(__temp_dict)
            logging.debug("Added service to all_services_dict {}".format(__temp_dict))
            return
        logging.debug("Service already in all_services_dict {}".format(__temp_dict))

    def __setnumbs(self, service) -> None:
        if service.get("protocol") == "tcp":
            self.numPors["tcp"] += 1
            logging.debug(f"TCP updated to: {self.numPors['tcp']}")
        if service.get("protocol") == "udp":
            logging.debug(f"UDP updated to: {self.numPors['udp']}")


# ------------------------------------------------------------------------------
# Files Class
# ------------------------------------------------------------------------------
class Files:
    """
    Files Class where all the files are made
        create_dir: Creates the directory
        save_results_file: Saves the results to a file
        write_hosts: Writes the host information to a file
        save_json: Saves the results to a json file
        save_xml: Saves the results to a xml file
        save_csv: Saves the results to a csv file
        save_sql3: Saves the results to a sql3 file
    """

    def set_save_dir() -> None:
        infi = HostInfo.inputFile.split(".")
        invalid_chars = "\<>:|?*;=!^"
        if len(infi) == 2:
            infi = infi[0]
            HostInfo.saveDirPorts = HostInfo.saveDir + "/open_ports"
        elif len(infi) == 3:
            infi = infi[0] + infi[1]
        if infi == "":
            infi = "set_save_dir"
        for char in infi:
            if char in "\ ":
                infi = infi.replace(char, "")
                logging.debug(f"Removed {char} from {infi}")
            elif char == invalid_chars:
                infi = infi.replace(char, "_")
                logging.debug(f"Removed {char} from {infi}")

        logging.debug(f"Input file: {infi}")
        HostInfo.saveDir = infi + "_" + "nmap_results"
        HostInfo.saveDirPorts = HostInfo.saveDir + "/open_ports"

    def save_all() -> None:
        try:
            Files.save_ports_file()
            Files.writehosts()
            Files.save_results_file()
            Files.save_json()
            Files.save_csv()
            Files.save_xml()
            Files.save_html()
        except Exception as e:
            logging.error(f"Error in save_all: {e}")

    def find_input_file() -> None:
        # look in current directory for a .gnmap
        files = [f for f in os.listdir(".") if os.path.isfile(f)]
        for f in files:
            # If it ends with any of the SUPPORTEDFILES
            if f.endswith(tuple(SUPPORTEDFILES)):
                print("No input provided found %s would you like to use?" % f)
                try:
                    ans = input("Enter Y/N to continue:")[0].lower()
                except IndexError:
                    ans = "y"
                if ans == "y":
                    HostInfo.inputFile = f
                    break
                elif ans == "n":
                    continue
                else:
                    print("Invalid input")
                    sys.exit(1)
        if HostInfo.inputFile == "":
            logging.critical("No input file provided or found, exiting")
            main.help_screen()
            sys.exit(1)
        else:
            Files.set_save_dir()
            logging.info("Using %s as input file" % HostInfo.inputFile)

    def create_dir() -> None:
        Files.set_save_dir()
        if Flag.force:
            Files.force_save()
        logging.info("Creating %s directory" % HostInfo.saveDir)
        # elif: Check to see if the directory is empty
        if not os.path.exists(HostInfo.saveDir):
            os.makedirs(HostInfo.saveDir)
        elif os.listdir(HostInfo.saveDir):
            logging.critical("Directory %s is not empty" % HostInfo.saveDir)
            sys.exit(1)
        if not os.path.exists(HostInfo.saveDirPorts):
            os.makedirs(HostInfo.saveDirPorts)
        elif os.listdir(HostInfo.saveDirPorts):
            logging.critical("Directory %s is not empty" ^ HostInfo.saveDirPorts)
            sys.exit(1)

    def clean_dir():
        # get a list of all the directories
        dirs = [d for d in os.listdir(".") if os.path.isdir(d)]
        for dir in dirs:
            if not dir.endswith("_nmap_results") or not Files.confirm(dir):
                continue
            Files.__deledir(dir)
        logging.info("Closing log file")
        logging.shutdown()
        os.remove(LOGFILE)
        print("All files removed")
        sys.exit(0)

    def force_save():
        Files.set_save_dir()
        Files.__deledir(HostInfo.saveDir)
        logging.info("All Files removed from %s" % HostInfo.saveDir)

    def confirm(dir):
        print("This will remove all files from %s" % dir)
        try:
            ans = input("Enter Y/N to continue:")[0].lower()
        except IndexError:
            ans = "y"
        if ans == "y":
            return True
        elif ans == "n":
            return False
        else:
            print("Invalid input")
            sys.exit(1)

    def __deledir(dir):
        logging.info("Trying to delete files")
        try:
            logging.info("Removing %s" % dir)
            if os.path.exists(dir):
                shutil.rmtree(dir)
        except OSError as e:
            logging.critical(e)
            sys.exit(1)

    def save_results_file() -> None:
        services, ports, all, hosts, tcp, udp = [], [], [], [], [], []
        logging.debug("Getting Sublists")
        for allServ in HostInfo.all_service_list:
            services.append(allServ.get("service") + " " + allServ.get("version"))
            ports.append(allServ.get("port"))
            _all_lst = [
                allServ.get("port"),
                allServ.get("state"),
                allServ.get("protocol"),
                allServ.get("service"),
                allServ.get("version"),
            ]
            _all_join = "/".join(_all_lst)
            all.append(_all_join)
            if "tcp" in allServ.get("protocol"):
                tcp.append(allServ.get("port"))
            if "udp" in allServ.get("protocol"):
                udp.append(allServ.get("port"))
        for host in HostInfo.host_dict:
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
            with open(HostInfo.saveDir + "/" + ftype + ".txt", "a") as f:
                f.write("\n".join(data[ftype]))
                files.append(ftype + ".txt")

        logging.debug("Files created: %s" % ", ".join(files))

    def writehosts() -> None:
        with open(HostInfo.saveDir + "/" + "HostInfo.txt", "a") as f:

            # get total number of hosts
            f.write("#Total Hosts: %s\n" % len(HostInfo.host_dict))
            f.write("#Total Services: %s\n" % len(HostInfo.all_service_list))
            f.write("#Total TCP Services: %s\n" % HostInfo.numPors.get("tcp"))
            f.write("#Total UDP Services: %s\n" % HostInfo.numPors.get("udp"))

            f.write("\n")
            for host in HostInfo.host_dict:
                f.write("Host: " + host + "\n")
                tempList = []
                for all in HostInfo.host_dict[host]:
                    __temp = []
                    for port in all:
                        if all[port] == None:
                            __temp.append("None")
                        __temp.append(all[port])
                    all = "/".join(__temp)
                    tempList.append(all)
                f.write("Ports: " + ", ".join(tempList) + "\n")
                f.write("\n")
            logging.debug("Files created: %s" % "HostInfo.txt")

    def save_ports_file() -> None:
        logging.info("Creating files in " + HostInfo.saveDirPorts)
        files = []
        for service in HostInfo.all_service_list:
            file = "%s_%s_%s_%s.txt" % (
                service.get("port"),
                service.get("state"),
                service.get("protocol"),
                service.get("service"),
            )
            files.append(file)
            with open(HostInfo.saveDirPorts + "/" + file, "a") as f:
                for host in HostInfo.host_dict:
                    if service in HostInfo.host_dict[host]:
                        f.write("%s\n" % host)
        logging.debug("Files created: %s" % ", ".join(files))

    def save_json() -> None:
        import json

        with open(HostInfo.saveDir + "/" + "HostInfo.json", "w") as f:
            json.dump(HostInfo.host_dict, f, indent=4)
        logging.debug("Files created: %s" % "HostInfo.json")

    def save_csv() -> None:
        import csv

        with open(HostInfo.saveDir + "/" + "HostInfo.csv", "w") as f:
            writer = csv.writer(f)
            writer.writerow(
                ["Host", "Port", "Protocol", "Owner", "Service", "RPC Info", "Version"]
            )
            for host in HostInfo.host_dict:
                for service in HostInfo.host_dict[host]:
                    writer.writerow(
                        [
                            host,
                            service.get("port"),
                            service.get("protocol"),
                            # service["owner"],
                            service.get("service"),
                            # service["rpc_info"],
                            service.get("version"),
                        ]
                    )
        logging.debug("Files created: %s" % "HostInfo.csv")

    def save_xml() -> None:

        import xml.etree.ElementTree as ET

        root = ET.Element("HostInfo")
        for host in HostInfo.host_dict:
            hostElement = ET.SubElement(root, "Host")
            hostElement.set("name", host)
            for service in HostInfo.host_dict[host]:
                serviceElement = ET.SubElement(hostElement, "Service")
                serviceElement.set("port", service.get("port"))
                serviceElement.set("protocol", service.get("protocol"))
                serviceElement.set("state", service.get("state"))
                serviceElement.set("service", service.get("service"))
                serviceElement.set("version", service.get("version"))
                # serviceElement.set("rpc_info", service["rpc_info"])
                # serviceElement.set("owner", service["owner"])

        from xml.dom import minidom

        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
        with open(HostInfo.saveDir + "/" + "HostInfo.xml", "w") as f:
            f.write(xmlstr)
        # tree.write(HostInfo.saveDir + "/" + "HostInfo.xml")
        logging.debug("Files created: %s" % "HostInfo.xml")

    def save_html() -> None:
        head = """<!DOCTYPE html><html><head><meta name=viewport content="width=device-width, initial-scale=1"><style>h1{text-align:center;background:#161b22;font-size:50px;font-family:"Times New Roman",Times,serif;color:#ddd}body{background:#0d1117;font-family:'Roboto',sans-serif;overflow:scroll;overflow-x:hidden;text-align:center}.wrapper{width:45rem;margin-inline:auto}.example::-webkit-scrollbar{display:none}.collapsible{text-transform:uppercase;font-size:1.25em;font-weight:900;background:none,linear-gradient(45deg,#1030ff8e,#3794d269);background-size:400%;animation:bg-animation 20s infinite alternate;cursor:pointer;padding:18px;width:100%;text-align:center;outline:2px ridge rgba(0,0,0,.6);border-radius:2rem;font-size:15px}.active,.collapsible:hover{background:none,linear-gradient(45deg,#1030ff48,#1030ffa6);background-size:400%;animation:bg-animation 1s infinite alternate}.content{padding:0 18px;max-height:0;background:#161b22;overflow:hidden;text-align:justify;transition:max-height .2s ease-out;margin-inline:auto;width:90%}.collapsible,.content,.sub-content{margin-bottom:5px;color:white}.sub-content{padding:5px;font-size:15px}.sub-content:hover{background:#161b22}@keyframes bg-animation{0%{background-position:left}100%{background-position:right}}.github-corner{position:sticky;bottom:0;right:0;text-align:right}.gh{text-decoration:none;color:white;text-transform:uppercase}.gh:hover{text-decoration:none;color:yellow}.gh:focus{text-decoration:none;color:orange}.gh:active{text-decoration:none;color:teal}</style></head><body><h1><a class=gh href=https://github.com/timothy90990/Automate title=a>Automate Results</a></h1><div class=wrapper>
        """

        close = """</div><script>var coll=document.getElementsByClassName("collapsible");var i;for(i=0;i<coll.length;i++){coll[i].addEventListener("click",function(){this.classList.toggle("active");var a=this.nextElementSibling;if(a.style.maxHeight){a.style.maxHeight=null}else{a.style.maxHeight=a.scrollHeight+"px"}})};</script></body></html>
        """

        with open(HostInfo.saveDir + "/" + "Automate.html", "w") as f:
            f.write(head)
            for host in HostInfo.host_dict:
                f.write(
                    '<button type="button" class="collapsible">%s</button><div class="content">'
                    % host
                )
                for service in HostInfo.host_dict[host]:
                    f.write(
                        """<p>
                            <a class="sub-content"><strong>Port:</strong> %s</a>
                            <a class="sub-content"><strong>Protocol:</strong> %s</a>
                            <a class="sub-content"><strong>State:</strong> %s</a>
                            <a class="sub-content"><strong>Service:</strong> %s</a>
                            <a class="sub-content"><strong>Version:</strong> %s</a>
                        </p>
                        """
                        % (
                            service.get("port"),
                            service.get("protocol"),
                            service.get("state"),
                            service.get("service"),
                            service.get("version"),
                        )
                    )
                    # When there are no more services beak
                    if service == HostInfo.host_dict[host][-1]:
                        break
                else:
                    f.write(
                        """<a class="sub-content"><strong>No Service Found</strong></a>"""
                    )
                f.write("</div>")
            f.write(close)

        # Open the file in the default browser
        import webbrowser

        new = 2
        file = "file://" + os.path.realpath(HostInfo.saveDir + "/" + "Automate.html")
        webbrowser.open(file, new=new)


# ------------------------------------------------------------------------------
# Nmap Parser Class
# ------------------------------------------------------------------------------
class NmapParse:
    def nmap_parser() -> None:
        with open(HostInfo.inputFile) as f:
            data = f.read()
        try:
            if HostInfo.inputFile.endswith(".xml"):
                NmapParse.xml.parse(data)
            if HostInfo.inputFile.endswith(".gnmap"):
                NmapParse.gnmap.parse(data)
            if HostInfo.inputFile.endswith(".nmap"):
                NmapParse.nmap.parse(data)
        except NotImplementedError as e:
            logging.critical("NotImplementedError - Nmap Parser - (%s)" % e)
            sys.exit(1)
        except Exception as e:
            logging.critical("Parsing file exiting (%s)" % e)
            sys.exit(1)

    class nmap:
        def parse(file) -> None:
            raise NotImplementedError(
                "NMAP FILE TYPE NOT SUPPORTED ON VERSION %s" % VERSION
            )
            logging.info("Parsing NMAP file %s" % HostInfo.inputFile)

    class xml:
        def parse(data) -> dict:
            """
            Takes in an XML file from Nmap and parses it into a dictionary

            Returns:
                dict: Dictionary of hosts and services
                dict{host: [service, service, service], host: [service, service, service]}
            """
            import xml.etree.ElementTree as ET

            logging.info("Parsing XML file %s" % HostInfo.inputFile)
            temp_dict = {}
            root = ET.fromstring(data)
            host_data = root.findall("host")
            for x in host_data:
                ip = x.find("address").get("addr")
                temp_dict[ip] = []
                ports = x.findall("ports/port")
                for port in ports:
                    temp_dict[ip].append(
                        {
                            "port": port.get("portid"),
                            "state": port.find("state").get("state"),
                            "protocol": port.get("protocol"),
                            "service": port.find("service").get("name"),
                            "version": port.find("service").get("product"),
                        }
                    )
                    for key in temp_dict[ip][-1]:
                        if temp_dict[ip][-1][key] is None:
                            temp_dict[ip][-1][key] = ""

            HostInfo.update_host(update=temp_dict)
            return temp_dict

    class gnmap:
        def parse(data) -> None:
            # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
            logging.info("Parsing GNMAP file ")
            # All of the hosts
            hosts = NmapParse.gnmap.findhosts(data)
            # All of the live hosts
            for host in hosts:
                if NmapParse.gnmap.hoststatus(host, data):
                    ports = NmapParse.gnmap.hostports(host, data)
                    HostInfo.update_host(update={host: ports})

        def findhosts(file_contents) -> list:
            """
            Pass in the file contents and return a list of hosts

            for each line regex the for the ip address
            as long as it follows this format
            Host: <ip> <hostname>
            """
            import re

            regex = re.compile(r"Host: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
            hosts = []
            for line in file_contents.splitlines():
                if regex.search(line):
                    hosts.append(regex.search(line).group(1))
            return sorted(list(set(hosts)))

        def hoststatus(host, file_contents) -> bool:
            """
            Pass in a an host ip and the file contents and it will return True if the host is up

            Host: <host> (<wildcard>)	Status: Up
            return True if up
            return False if down
            """
            import re

            regex = re.compile(r"Host: %s.*Status: (\w+)" % host)
            for line in file_contents.splitlines():
                if regex.search(line):
                    if regex.search(line).group(1) == "Up":
                        return True
            return False

        def hostports(host, file_contents) -> list:
            """
            Pass in a an host ip and the file contents and it will return a list of ports

            First get the line that contains the ports
            Host: <host> (<wildcard>)	Ports:

            Then find all of the ports that follow this format
            port/state/protocol/owner/service/rpc_info/version/
            """
            import re

            regex = re.compile(r"Host: %s.*Ports: (\w+)" % host)
            line_ports = ""
            dict_port = {}
            list_ports = []
            for line in file_contents.splitlines():
                if regex.search(line):
                    # Remove the regex match from the line
                    line_ports = line.replace(regex.search(line).group(0), "")
                    break
            # print("%s ---> %s" % (host, line_ports))
            # If the line_ports is empty then there are no ports open
            if not line_ports:
                return list_ports
            # Get the ports from the line /port/state/protocol/owner/service/rpc_info/version/
            regex = re.compile(r"(\d+)/(\w*)/(\w*)/(\w*)/(\w*)/(\w*)/(\w*)/")
            ports = regex.findall(line_ports)
            for port in ports:
                dict_port = {
                    "port": port[0],
                    "state": port[1],
                    "protocol": port[2],
                    "owner": port[3],
                    "service": port[4],
                    "rpc_info": port[5],
                    "version": port[6],
                }
                list_ports.append(dict_port)
            return list_ports


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
                logging.debug("Flag found: %s" % arg)
                if arg in ["-h", "--help"]:
                    self.help = True
                    break
                elif arg in ["-i", "-iL", "--input", "--input-list"]:
                    logging.debug("Input file flag found")
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
                        logging.debug("Input file: %s" % sys.argv[i + 1])
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
class main:
    def main() -> None:
        if Flag.help:
            main.help_screen()
            sys.exit(1)
        if Flag.clean:
            Files.clean_dir()
        if Flag.inputFlag == False and HostInfo.inputFile == "":
            logging.debug("No input file specified searching for file")
            Files.find_input_file()
        NmapParse.nmap_parser()

        Files.create_dir()
        Files.save_all()

        # Finish
        print("Finished parsing, files created, check %s directory" % HostInfo.saveDir)

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
        print(main.header.__doc__.format(VERSION, AUTHOR, color, bcolors.RESET))
        print("Python Version % s" % PYTHON_VERSION)
        print(
            "This program is used to take a gnmap file and parse for easier automation"
        )


###############################################################################
if __name__ == "__main__":
    start_time = time.time()
    HostInfo = HostInfo()
    Flag = Flag()
    main.header()
    main.main()
    logging.info("Finished in %s seconds" % (time.time() - start_time))
