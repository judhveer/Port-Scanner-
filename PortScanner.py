
import sys
from argparse import ArgumentParser
import socket
from threading import Thread
from time import time

open_ports = []

def prepare_args():
    """ Prepare arguments
        
        return:
            args(argparse.Namespace)
    """
    parser = ArgumentParser(description="Python Based Fast Port Scanner",usage="%(prog)s 192.168.1.2",epilog="Example - %(prog)s -s 20 -e 40000 -t 500 -V 192.168.1.2")
    parser.add_argument(metavar="IPv4",dest="ip",help="host to scan")
    parser.add_argument("-s","--start",dest="start",metavar="",type=int,help="starting port",default=1)
    parser.add_argument("-e","--end",dest="end",metavar="",type=int,help="ending port",default=1000)
    parser.add_argument("-t","--threads",dest="threads",metavar="",type=int,help="threads to use",default=500)
    parser.add_argument("-V","--verbose",dest="verbose",action="store_true",help="verbose output")
    parser.add_argument("-v","--version",action="version",version="%(prog)s 1.0",help="Display version")

    args = parser.parse_args()
    return args


def prepare_ports(start:int, end:int):
    # generator function for ports

    # arguments:
        # start(int) - starting port
        # end(int) - ending port
    for port in range(start, end+1):
        yield port  

def scan_port():
    # scan ports
    while True:
        try:
            s = socket.socket()
            s.settimeout(1)
            port = next(ports)
            s.connect((arguments.ip, port))
            open_ports.append(port)
            print(f"Port {port} is OPEN")
            if arguments.verbose:
                print(f"\r{open_ports}", end="")

        except (ConnectionRefusedError, socket.timeout):
            continue
        except StopIteration:
            break



def prepare_threads(threads:int):
    # create, start, join threads
        # arguments:
            # threads(int) - Number of threads to use

    thread_list = []
    for _ in range(threads+1):
        thread_list.append(Thread(target=scan_port))

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

target = '"Invalid Hostname"'
print("-" * 60)
print("Python Port Scanner")
print("-" * 60)



arguments = prepare_args()

        
ports = prepare_ports(arguments.start, arguments.end)

if (len(sys.argv[1]) >= 3 or sys.argv[1] == '-' ):
    try: 
        target = socket.gethostbyname(sys.argv[1])
    except socket.gaierror:
        print("Hostname is incorrect")
        sys.exit()
print("Scanning Target", target)
start_time = time()
prepare_threads(arguments.threads)
end_time = time()

if arguments.verbose:
    print()
# print(f"Port {p} is OPEN")
print(f"Time Taken -> {round(end_time-start_time,2)}")
