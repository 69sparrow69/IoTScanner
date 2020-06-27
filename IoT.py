#!/usr/bin/env python3

# MUD Profile Examples: https://iotanalytics.unsw.edu.au/mudprofiles

import json
import time
import nmap
import re
#from six.moves import input

#These arrays store the TCP and UDP ports that scanned
#and found open on the IOT device
nmapTCP = []
nmapUDP = []

#These arrays store the unique TCP and UDP source ports that are
#allowed to be open, according to the IoT device's MUD file
uniqueMUDtcp = []
uniqueMUDudp = []

MUDtcp = []
MUDudp = []

def jsonPorter(configx):

    #These strings are used temporarily to contain
    #all TCP and UDP substrings from the MUD file
    TCPsourceStrings = ""
    UDPsourceStrings = ""

    #creates temporary array to store the TCP and UDP
    #ports from the MUD profile as some ports are repeated
    #in the MUD profile
    # uniqueMUDTCP = []
    # uniqueMUDUDP = []

    #Takes in the JSON file from user input, formats it
    with open(configx, 'r') as MUD:
        f1 = json.load(MUD)
    MUDtext = json.dumps(f1, indent=2)

    #################### Extracting TCP ports ####################

    #Extracting TCP ports, using regex
    portSnatcher = re.compile("tcp.*\s.*\s.*\s.*: \d+")
    result = portSnatcher.findall(MUDtext)

    #Cleaning output from MUD file and
    #appending to a TCP substring for port extraction later
    for index,item in enumerate(result):
        item.split()
        if 'source-port' in item:
            TCPsourceStrings += item

    #TCP ports are extractd and appended to a temporary TCP port array
    global MUDtcp
    MUDtcp = re.findall('\d+', TCPsourceStrings)
    # tcpTemp.append(port)
    # print tcpTemp

    #################### Extracting UDP ports ####################

    #Extracting UDP ports, using regex
    portSnatcher = re.compile("udp.*\s.*\s.*\s.*: \d+")
    result = portSnatcher.findall(MUDtext)

    #Cleaning output from MUD file and
    #appending to a UDP substring for port extraction later
    for index,item in enumerate(result):
        item.split()
        if 'source-port' in item:
            UDPsourceStrings += item

    #UDP ports are extractd and appended to a temporary UDP port array
    global MUDudp
    MUDudp = re.findall('\d+', UDPsourceStrings)

    # #this function only adds the unique TCP source-ports
    # #to the global MUDTCP array which is later presented to the user
    for port in MUDtcp:
        if port not in uniqueMUDtcp:
            uniqueMUDtcp.append(port)

    uniqueMUDtcp.sort()

    # #this program only adds the unique UDP source-ports
    # #to the global MUDTCP array which is later presented to the user
    for port in MUDudp:
        if port not in uniqueMUDudp:
            uniqueMUDudp.append(port)

    uniqueMUDudp.sort()

    # all the unique TCP and UDP ports have been added
    # to allPorts and is shown to the user
    # print allPorts

    # function returns the collection of all ports
    with open('ScanResults.txt', 'a') as f:
        f.write("The MUD file requires these TCP ports to be open:\n")
        for item in uniqueMUDtcp:
            f.write(item)
            f.write("\n")
        f.write("The MUD file requires these UDP ports to be open:\n")
        for item in uniqueMUDudp:
            f.write(item)
            f.write("\n")

def nmapScan(ip, portList, flags):

    result = ""
    scannedPorts = []

    #initiating the nmap port scanner
    nm = nmap.PortScanner()

    #this function scans the port
    #that is passed in to it
    for port in portList:

        #general command for scanning
        #could be improved to be stealthy
        nm.scan(ip,str(port),flags)
        # nm.scan(hosts=ip,arguments='-Pn')

        for host in nm.all_hosts():
            #Standard scanning procedure
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()

                for scannedPort in lport:
                    #Presenting the ports, portocols and status
                    result += ('\n' + ('Protocol : %s\t port : %s\tstate : %s' % (proto, scannedPort, nm[host][proto][scannedPort]['state'])))

                    #Scanned ports are added to the scannedPorts array
                    scannedPorts.append(scannedPort)

                    if proto=="TCP":
                    #Scanned TCP ports are added to the nmapTCP array
                        nmapTCP.append(scannedPort)

                    if proto=="UDP":
                    #Scanned UDP ports are added to the nmapTCP array
                        nmapUDP.append(scannedPort)

    #We present the results and return the total scanned ports
    print (result)

    with open('ScanResults.txt', 'a') as f:
        f.write(result)
        f.write("\n")

def nmapFullScan(ip,flags):

    result = ""
    scannedPorts = []
    # global nmapTCP
    # global nmapUDP

    #initiating the nmap port scanner
    nm = nmap.PortScanner()


    # for port in range(1,65535):
        #general command for scanning
        #could be improved to be stealthy

    # nm.scan(ip,str('1-65535'), '-Pn')
    nm.scan(hosts=ip,arguments=flags)

    for host in nm.all_hosts():
        #Standard scanning procedure
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()

            #the results are solted
            # lport.sort()

            for scannedPort in lport:
                #Presenting the ports, portocols and status
                if (nm[host][proto][scannedPort]['state'] == 'open'):
                    result += ('\n' + ('Protocol : %s\t port : %s\tstate : %s' % (proto, scannedPort, nm[host][proto][scannedPort]['state'])))

                #Scanned ports are added to the scannedPorts array
                scannedPorts.append(scannedPort)

                if proto=="tcp":
                #Scanned TCP ports are added to the nmapTCP array
                    print ("Under TCP")
                    print (scannedPort)
                    
                    nmapTCP.append(scannedPort)

                if proto=="udp":
                #Scanned UDP ports are added to the nmapTCP array
                    print ("Under UDP")
                    print (scannedPort)
                    
                    nmapUDP.append(scannedPort)


    nmapTCP.sort()
    nmapUDP.sort()
    print ("After Sorting in full scan")
    print (nmapTCP)
    print (nmapUDP)

    #We present the results and return the total scanned ports
    print (result)

    with open('ScanResults.txt', 'a') as f:
        # f.write("\nScan results (open ports) for all ports:")
        f.write(result)

def masterScanner(inputtedIP, inputtedMUD):

    ip = inputtedIP
    MUDfile = inputtedMUD

    with open('ScanResults.txt', 'a') as f:
        f.write("- - - - - - - - - - - - - - - - - - - - \n")
        f.write("Current scanning: " + ip + "\n")

    #We present the user with which ports are mentioned in the MUD file
    jsonPorter(MUDfile)

    with open('ScanResults.txt', 'a') as f:
        f.write("\nScanning TCP ports mentioned in the MUD file:")
    nmapScan(ip,uniqueMUDtcp,'-Pn -f')
    #nmapScan(ip,uniqueMUDtcp,'-Pn')

    with open('ScanResults.txt', 'a') as f:
        f.write("\nScanning UDP ports mentioned in the MUD file:")
    nmapScan(ip,uniqueMUDudp, '-Pn -sU')
    #nmapScan(ip,uniqueMUDudp, '-Pn')

    with open('ScanResults.txt', 'a') as f:
        f.write("\nPerforming complete scan of IP, only open ports are listed:")
    nmapFullScan(ip, '-Pn -f')
    nmapFullScan(ip, '-Pn -sU')

    print ("Before else ifs")
    print (nmapTCP)
    print (nmapUDP)

    with open('ScanResults.txt', 'a') as f:

        if uniqueMUDtcp == nmapTCP:
            f.write("\nTCP Ports are compliant, no extra open ports found outside MUD instructions.\n")
        elif len(nmapTCP) > len(uniqueMUDtcp):
            f.write("\nMore TCP ports are open than needed. TCP Ports are non-compliant.\n")
        else:
            f.write("\nMUD recommends having more TCP ports open, than on IoT currently. Device is over-protected.\n")


        if uniqueMUDudp == nmapUDP:
            f.write("UDP Ports are compliant, no extra open ports found outside MUD instructions.\n")
        elif len(nmapUDP) > len(uniqueMUDudp):
            f.write("\nMore UDP ports are open on IoT than needed. UDP Ports are non-compliant.\n")
        else:
            f.write("\nMUD recommends having more UDP ports open, than on IoT currently. Device is over-protected.\n")

#Asking the user for how many IP addresses to scan.
#DO NOT REMOVE, this breaks the loop on the 'for' loop.
print ("How many IP addresses (1 or more) do you wish to scan: ")
numberofIPs = int(input())
print ("What is the name of the json MUD file (include the .json extension): ")
MUDfile = input()
print ("\nPlease note, this program determines if the NUMBER of ports on your IoT matches the number of TCP/UDP ports in the MUD.")
print ("\nThis terminal will display content for troubleshooting only. The final esults of this scan will be inside 'ScanResults.txt' in the same directory as this file.")

with open('IP_Addresses.txt','r+') as f:
    ip = f.read().splitlines()
    for i in range(0,numberofIPs):
        masterScanner(ip[i], MUDfile)