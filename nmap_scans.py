import nmap

#init scanner nm
nm = nmap.PortScanner()

#testing, will implement it into a main script in the future
target = '' 
arguments = '-p-'

nm.scan(target, arguments)
#command executed
print("command: ", nm.command_line())

#scan summary
print("scan summary: ")
for host in nm.all_hosts():
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())

    # Print open ports
    for pro in nm[host].all_protocols():
        print('protocol : %s' % pro)

        ports = nm[host][pro].keys()
        for port in ports:
            print('port : %s\tState : %s' % (port, nm[host][pro][port]['state']))