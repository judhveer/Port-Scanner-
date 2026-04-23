import sys
from argparse import ArgumentParser
import socket
from threading import Thread, Lock
from time import time
from datetime import datetime

# ── Shared state ─────────────────────────────────────────────────────────────
open_ports = []          # list of dicts: {port, service, banner}
lock = Lock()            # guards open_ports against race conditions

# ── Common port → service name map (fallback when banner is empty) ────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    6443: "Kubernetes", 2375: "Docker", 9200: "Elasticsearch",
    11211: "Memcached", 1433: "MSSQL", 1521: "Oracle DB", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 20: "FTP-Data", 69: "TFTP",
    161: "SNMP", 389: "LDAP", 636: "LDAPS", 1883: "MQTT",
    8888: "HTTP-Alt2", 9090: "Prometheus", 4200: "Angular-Dev",
    3000: "Node-Dev", 5000: "Flask-Dev", 8000: "Django-Dev",
}

# ── Argument parser ───────────────────────────────────────────────────────────
def prepare_args():
    """
    Parse and return CLI arguments.
    Usage: python port_scanner.py <host> [-s START] [-e END] [-t THREADS] [-V] [-o FILE]
    """
    parser = ArgumentParser(
        description="Python Multi-Threaded Port Scanner with Banner Grabbing",
        usage="%(prog)s 192.168.1.2",
        epilog="Example: %(prog)s -s 1 -e 1024 -t 300 -V -o results.txt 192.168.1.2",
    )
    parser.add_argument(metavar="IPv4/Hostname", dest="ip",
                        help="Host or IP address to scan")
    parser.add_argument("-s", "--start", dest="start", metavar="", type=int,
                        default=1, help="Starting port (default: 1)")
    parser.add_argument("-e", "--end", dest="end", metavar="", type=int,
                        default=1000, help="Ending port (default: 1000)")
    parser.add_argument("-t", "--threads", dest="threads", metavar="", type=int,
                        default=300, help="Number of threads (default: 300)")
    parser.add_argument("-V", "--verbose", dest="verbose", action="store_true",
                        help="Print each open port as it is found")
    parser.add_argument("-o", "--output", dest="output", metavar="FILE",
                        default=None, help="Save results to a text file")
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 2.0")
    return parser.parse_args()


# ── Port generator (shared across threads) ────────────────────────────────────
def prepare_ports(start: int, end: int):
    """Yield ports from start to end (inclusive)."""
    for port in range(start, end + 1):
        yield port


# ── Banner grabbing ───────────────────────────────────────────────────────────
def grab_banner(s: socket.socket) -> str:
    """
    Attempt to read a service banner from an already-connected socket.
    Sends an HTTP HEAD request as a probe to trigger HTTP servers.
    Returns the first line of the response, or an empty string on failure.
    """
    try:
        # Probe: many services (HTTP, FTP, SSH, SMTP) send a banner on connect.
        # For HTTP we need to send a request first.
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
        # Return only the first meaningful line
        first_line = banner.splitlines()[0] if banner else ""
        return first_line[:80]    # cap at 80 chars for clean display
    except Exception:
        return ""


# ── Identify service name ─────────────────────────────────────────────────────
def identify_service(port: int, banner: str) -> str:
    """
    Return a human-readable service name.
    Priority: banner content > common port map > 'Unknown'
    """
    banner_lower = banner.lower()
    if "ssh" in banner_lower:
        return "SSH"
    if "ftp" in banner_lower:
        return "FTP"
    if "smtp" in banner_lower or "mail" in banner_lower:
        return "SMTP"
    if "http" in banner_lower or "html" in banner_lower:
        return "HTTP"
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        return "MySQL"
    if "redis" in banner_lower:
        return "Redis"
    if "mongodb" in banner_lower:
        return "MongoDB"
    return COMMON_PORTS.get(port, "Unknown")


# ── Core scanner (runs in each thread) ───────────────────────────────────────
def scan_port():
    """
    Pull ports from the shared generator, attempt TCP connect,
    grab banner, identify service, and record results thread-safely.
    """
    while True:
        try:
            port = next(ports)
        except StopIteration:
            break

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((target, port))

            # Port is open — grab banner and identify service
            banner  = grab_banner(s)
            service = identify_service(port, banner)

            with lock:
                open_ports.append({"port": port, "service": service, "banner": banner})
                if arguments.verbose:
                    tag = f"[{service}]" if service != "Unknown" else ""
                    print(f"  [+] Port {port:<6} OPEN  {tag}")

        except (ConnectionRefusedError, socket.timeout, OSError):
            pass
        finally:
            try:
                s.close()
            except Exception:
                pass


# ── Thread management ─────────────────────────────────────────────────────────
def prepare_threads(n: int):
    """Spawn n threads, start all, then join all."""
    threads = [Thread(target=scan_port, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


# ── Final report ──────────────────────────────────────────────────────────────
def print_report(elapsed: float, output_file=None):
    """
    Print a formatted table of all open ports.
    Optionally write the same report to a file.
    """
    # Sort by port number
    results = sorted(open_ports, key=lambda x: x["port"])

    lines = []
    lines.append("")
    lines.append("=" * 65)
    lines.append(f"  SCAN REPORT — {target}")
    lines.append(f"  Ports scanned : {arguments.start}–{arguments.end}")
    lines.append(f"  Threads used  : {arguments.threads}")
    lines.append(f"  Scan started  : {scan_start_str}")
    lines.append(f"  Time taken    : {round(elapsed, 2)}s")
    lines.append(f"  Open ports    : {len(results)}")
    lines.append("=" * 65)

    if results:
        lines.append(f"  {'PORT':<8} {'SERVICE':<16} {'BANNER'}")
        lines.append("  " + "-" * 61)
        for r in results:
            banner_display = r["banner"] if r["banner"] else "—"
            lines.append(f"  {r['port']:<8} {r['service']:<16} {banner_display}")
    else:
        lines.append("  No open ports found in the specified range.")

    lines.append("=" * 65)
    lines.append("")

    output = "\n".join(lines)
    print(output)

    if output_file:
        try:
            with open(output_file, "w") as f:
                f.write(output)
            print(f"  [*] Results saved to: {output_file}")
        except IOError as e:
            print(f"  [!] Could not write to file: {e}")


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("-" * 65)
    print("  Python Port Scanner v2.0  |  Multi-threaded + Banner Grabbing")
    print("-" * 65)

    arguments = prepare_args()

    # Resolve hostname to IP — use arguments.ip (not sys.argv[1])
    # This is correct regardless of flag order on the command line.
    try:
        target = socket.gethostbyname(arguments.ip)
    except socket.gaierror:
        print(f"  [!] Could not resolve hostname: {arguments.ip}")
        sys.exit(1)

    print(f"  Target   : {arguments.ip} ({target})")
    print(f"  Range    : {arguments.start} – {arguments.end}")
    print(f"  Threads  : {arguments.threads}")
    print("-" * 65)

    ports = prepare_ports(arguments.start, arguments.end)
    scan_start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if arguments.verbose:
        print("  Live results:")

    start_time = time()
    prepare_threads(arguments.threads)
    end_time = time()

    print_report(end_time - start_time, output_file=arguments.output)
