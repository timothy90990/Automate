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
Date: 10/25/2022
"""

import logging
import os
import random
import re
import shutil
import sys
import time


# ------------------------------------------------------------------------------
# Settings
# ------------------------------------------------------------------------------
PYTHON_VERSION = sys.version_info[0]
AUTHOR = "Timothy Stowe"
VERSION = "0.0.5"
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
            "port": service["port"],
            "state": service["state"],
            "protocol": service["protocol"],
            "service": service["service"],
            "version": service["version"],
        }
        if __temp_dict not in self.all_service_list:
            self.all_service_list.append(__temp_dict)
            logging.debug("Added service to all_services_dict {}".format(__temp_dict))
            return
        logging.debug("Service already in all_services_dict {}".format(__temp_dict))

    def __setnumbs(self, service) -> None:
        if service["protocol"] == "tcp":
            self.numPors["tcp"] += 1
            logging.debug(f"TCP updated to: {self.numPors['tcp']}")
        if service["protocol"] == "udp":
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
        Files.save_ports_file()
        Files.writehosts()
        Files.save_results_file()
        Files.save_json()
        Files.save_csv()
        Files.save_xml()
        Files.save_sql3()
        Files.save_html()

    def find_input_file() -> None:
        # look in current directory for a .gnmap
        files = [f for f in os.listdir(".") if os.path.isfile(f)]
        for f in files:
            # If it is a .gnmap file
            if f.endswith(".gnmap") or f.endswith(".xml") or f.endswith(".nmap"):
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
            services.append(allServ["service"] + " " + allServ["version"])
            ports.append(allServ["port"])
            _all_lst = [
                allServ["port"],
                allServ["state"],
                allServ["protocol"],
                allServ["service"],
                allServ["version"],
            ]
            _all_join = "/".join(_all_lst)
            all.append(_all_join)
            if "tcp" in allServ["protocol"]:
                tcp.append(allServ["port"])
            if "udp" in allServ["protocol"]:
                udp.append(allServ["port"])
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
            f.write("#Total TCP Services: %s\n" % HostInfo.numPors["tcp"])
            f.write("#Total UDP Services: %s\n" % HostInfo.numPors["udp"])

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
                service["port"],
                service["state"],
                service["protocol"],
                service["service"],
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
                            service["port"],
                            service["protocol"],
                            # service["owner"],
                            service["service"],
                            # service["rpc_info"],
                            service["version"],
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
                serviceElement.set("port", service["port"])
                serviceElement.set("protocol", service["protocol"])
                serviceElement.set("state", service["state"])
                serviceElement.set("service", service["service"])
                serviceElement.set("version", service["version"])
                # serviceElement.set("rpc_info", service["rpc_info"])
                # serviceElement.set("owner", service["owner"])

        from xml.dom import minidom

        xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
        with open(HostInfo.saveDir + "/" + "HostInfo.xml", "w") as f:
            f.write(xmlstr)
        # tree.write(HostInfo.saveDir + "/" + "HostInfo.xml")
        logging.debug("Files created: %s" % "HostInfo.xml")

    def save_sql3() -> None:
        import sqlite3

        conn = sqlite3.connect(HostInfo.saveDir + "/" + "HostInfo.db")
        c = conn.cursor()
        c.execute(
            "CREATE TABLE HostInfo (host text, port text, state text, protocol text, owner text, service text, rpc_info text, version text)"
        )
        for host in HostInfo.host_dict:
            for service in HostInfo.host_dict[host]:
                c.execute(
                    "INSERT INTO HostInfo VALUES (?,?,?,?,?,?,?,?)",
                    (
                        host,
                        service["port"],
                        service["state"],
                        service["protocol"],
                        "",  # service["owner"],
                        service["service"],
                        "",  # service["rpc_info"],
                        service["version"],
                    ),
                )
        conn.commit()
        conn.close()
        logging.debug("Files created: %s" % "HostInfo.db")

    def save_html() -> None:
        head = """
        <!DOCTYPE html>
        <html>
        <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        """

        style = """
        <style>
        .collapsible {
          background-color: rgb(0, 44, 138);
          color: white;
          cursor: pointer;
          padding: 18px;
          width: 100%;
          text-align: left;
          outline: 2px ridge rgba(0, 0, 0, .6);
          border-radius: 2rem;
          font-size: 15px;
        }

        .active, .collapsible:hover {
          background-color: #555;
        }

        .content {
          padding: 0 18px;
          max-height: 0;
          overflow: hidden;
          transition: max-height 0.2s ease-out;
          background-color: #f1f1f1;
        }
        
        .service {
          background-color: rgb(238, 238, 238);
          color: rgb(0, 0, 0);
          padding: 4px;
          width: 100%;
          text-align: left;
          outline: solid 1px rgba(0, 0, 0, .6);
          font-size: 15px;
        }
        </style>
        """

        head_2 = """
        </head>
        <body>
        <h1>Automate Results</h1>
        """

        script = """
        <script>
        var coll = document.getElementsByClassName("collapsible");
        var i;
        
        for (i = 0; i < coll.length; i++) {
          coll[i].addEventListener("click", function() {
            this.classList.toggle("active");
            var content = this.nextElementSibling;
            if (content.style.maxHeight){
              content.style.maxHeight = null;
            } else {
              content.style.maxHeight = content.scrollHeight + "px";
            } 
          });
        }
        </script>
        """
        close = """
        </body>
        </html>
        """

        with open(HostInfo.saveDir + "/" + "Automate.html", "w") as f:
            f.write(head)
            f.write(style)
            f.write(head_2)
            for host in HostInfo.host_dict:
                f.write(
                    '<button type="button" class="collapsible">%s</button><div class="content">'
                    % host
                )
                for service in HostInfo.host_dict[host]:
                    f.write(
                        """<p>
                            <a class="service"><strong>Port:</strong> %s</a>
                            <a class="service"><strong>Protocol:</strong> %s</a>
                            <a class="service"><strong>State:</strong> %s</a>
                            <a class="service"><strong>Service:</strong> %s</a>
                            <a class="service"><strong>Version:</strong> %s</a>
                        </p>
                        """
                        % (
                            service["port"],
                            service["protocol"],
                            service["state"],
                            service["service"],
                            service["version"],
                        )
                    )
                f.write("</div>")
            f.write(script)
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
        if HostInfo.inputFile.endswith(".xml"):
            NmapParse.xml.nmap_parser(HostInfo.inputFile)
        if HostInfo.inputFile.endswith(".gnmap"):
            NmapParse.gnmap.nmap_parser()
        if HostInfo.inputFile.endswith(".nmap"):
            NmapParse.nmap.nmap_parser()

    class nmap:
        # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
        def nmap_parser() -> None:
            logging.info("Parsing Nmap file")
            NmapParse.nmap.__line_extractor(HostInfo.inputFile)
            logging.info("Finished parsing Nmap file")

        def __line_extractor(inputFile) -> None:
            with open(inputFile, "r") as f:
                lines = f.readlines()
            host = ""
            port_lines = []
            for line in lines:
                if "Nmap scan report for" in line:
                    # Regex to extract the IP address
                    host = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)[0]
                if "open" in line:
                    port_lines.append(NmapParse.nmap.__port_extractor(line))
                if "MAC Address:" in line:
                    # serv_os = NmapParse.nmap.__os_extractor(line)
                    if port_lines:
                        logging.debug("Host Info: %s" % {host: port_lines})
                        HostInfo.update_host(update={host: port_lines})
                    host = ""
                    port_lines = []

        def __port_extractor(line) -> list:
            # Remove any new lines from line
            line = line.replace("\r", "").replace("\n", "")

            line = line.split(" ")
            port = line[0].split("/")[0]
            protocol = line[0].split("/")[1]
            # Search for the state
            for index, item in enumerate(line):
                if "open" in item:
                    state = item
                    # service is the remainder of the line
                    service = " ".join(line[index + 1 :])
                if "filtered" in item:
                    state = item
                    service = " ".join(line[index + 1 :])
            version = "N/A in Nmap file"
            temp_dict = {}
            temp_dict.update({"port": port})
            temp_dict.update({"state": state})
            temp_dict.update({"protocol": protocol})
            temp_dict.update({"service": service})
            temp_dict.update({"version": version})

            # Old version
            # retVal = [port, state, protocol, owner, service, rpc_info, version]
            logging.debug("Port line: %s" % temp_dict)
            return temp_dict

        def __os_extractor(line) -> str:
            os = line.split(" ")[3]
            os = os.replace("\n", "")
            os = os.replace(";", "")
            logging.debug("OS line: %s" % os)
            return os

    class xml:
        # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
        def nmap_parser(infile) -> None:
            import xml.etree.ElementTree as ET

            logging.info("Opening %s and extracting lines" % HostInfo.inputFile)
            tree = ET.parse(infile)
            root = tree.getroot()
            NmapParse.xml.__extractor(root)

        def __extractor(root) -> None:
            for host in root.findall("host"):
                ip_address = host.find("address").get("addr")
                try:
                    os = NmapParse.xml.__extract_os(host)
                except AttributeError:
                    os = ""
                allList = NmapParse.xml.__extract_all(host)
                HostInfo.update_host(update={ip_address: allList}, os={ip_address: os})

        def __extract_os(host) -> list:
            os = []
            os.append(host.find("os/osmatch").get("name"))
            os_accuracy = host.find("os/osmatch").get("accuracy")
            os.append(os_accuracy)
            logging.debug("OS line: %s" % os)
            return os

        def __extract_all(host) -> list:
            allList = []

            for port in host.findall("ports/port"):
                templist = {}
                serv = port.find("service").get("name")
                serv2 = port.find("service").get("product")
                if not serv:
                    serv = "unknown"
                if not serv2:
                    serv2 = "unknown"
                service = serv + " " + serv2
                templist.update({"port": port.get("portid")})
                templist.update({"state": port.find("state").get("state")})
                templist.update({"protocol": port.get("protocol")})
                templist.update({"service": service})
                templist.update({"version": port.find("service").get("version")})
                for item in templist:
                    if templist[item] == None or templist[item] == "":
                        templist[item] = "unknown"
                allList.append(templist)

            logging.debug("Port line: %s" % allList)
            return allList

    class gnmap:
        def nmap_parser() -> None:
            logging.info("Parsing Nmap file")
            __infileLines = []
            __infileLines = NmapParse.gnmap.__get_lines(__infileLines)
            for line in __infileLines:
                NmapParse.gnmap.__extractor(line)
            logging.info("Finished parsing Nmap file")

        def __get_lines(__infileLines) -> None:
            try:
                logging.info("Opening %s and extracting lines" % HostInfo.inputFile)
                with open(HostInfo.inputFile, "r") as f:
                    for line in f:
                        if line[0] == "#":
                            continue
                        elif "Ports:" in line:
                            __infileLines.append(line)
                return __infileLines
            except FileNotFoundError as e:
                logging.critical(e)
                sys.exit(1)
            except OSError as e:
                logging.critical(e)
                sys.exit(1)

        def __extractor(line: str) -> None:

            line = line.split()
            ip_address = line[1]
            allList = []
            for index, item in enumerate(line):
                if "Ports:" in item:
                    line = line[(index + 1) :]
                if "Ignored" in item:
                    line = line[: line.index("Ignored")]
            # line = line[4:-4]
            line = "".join(line)
            line = line.split(",")
            for ports_r in line:
                ports = NmapParse.gnmap.__ports_list(ports_r)
                allList.append(ports)
            HostInfo.update_host(update={ip_address: allList})

        def __ports_list(ports_r: list) -> list:
            # ($port, $state, $protocol, $owner, $service, $rpc_info, $version)
            invalid_chars = "\<>:|?*;=!^"
            for char in invalid_chars:
                if char in ports_r:
                    logging.debug("Invalid character %s found in: %s" % (char, ports_r))
                    ports_r = ports_r.replace(char, "_")
            ports = ports_r.split("/")
            logging.debug("Port line: %s" % ports)
            if ports == [""]:
                ports = [
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                    "unknown",
                ]
            ports = {
                "port": ports[0],
                "state": ports[1],
                "protocol": ports[2],
                "service": ports[3],
                "version": ports[4],
            }
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
