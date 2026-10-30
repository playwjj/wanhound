"""WanHound test bench target.

TCP  22    open      SSH banner
TCP  80    open      HTTP page titled like a router admin UI
TCP  8080  filtered  listener behind an iptables DROP
TCP  8443  closed    iptables REJECT with TCP reset
TCP  9000  filtered  iptables REJECT with ICMP port-unreachable
TCP  10000 closed    nothing listening (until the "open" control file appears)
UDP  53    open      answers every query with RA set (an "open resolver")
UDP  1900  open|filt iptables DROP
UDP  123   closed    nothing listening

Touch /tmp/open-10000 inside the container to start a listener on
10000 — the diff acceptance step.
"""
import os, socket, subprocess, threading, time

def sh(*cmd):
    subprocess.run(cmd, check=True)

for rule in (["-p", "tcp", "--dport", "8080", "-j", "DROP"],
             ["-p", "tcp", "--dport", "8443", "-j", "REJECT", "--reject-with", "tcp-reset"],
             ["-p", "tcp", "--dport", "9000", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"],
             ["-p", "udp", "--dport", "1900", "-j", "DROP"]):
    sh("iptables", "-A", "INPUT", *rule)

def tcp(port, handler):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port)); s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=handler, args=(c,), daemon=True).start()

def ssh(c):
    try:
        c.sendall(b"SSH-2.0-OpenSSH_9.6 testbench\r\n"); c.settimeout(2); c.recv(256)
    except OSError: pass
    c.close()

def http(c):
    try:
        c.settimeout(2); c.recv(4096)
        body = b"<html><head><title>TP-LINK Router Login</title></head><body>bench</body></html>"
        c.sendall(b"HTTP/1.0 200 OK\r\nServer: GoAhead-Webs\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n%s" % (len(body), body))
    except OSError: pass
    c.close()

def quiet(c):
    try:
        c.settimeout(2); c.recv(256)
    except OSError: pass
    c.close()

def dns():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("0.0.0.0", 53))
    while True:
        q, addr = s.recvfrom(512)
        if len(q) < 12: continue
        # Echo the question back as a response with RA, one fake A record.
        r = bytearray(q); r[2] |= 0x80; r[3] = 0x80; r[7] = 1
        r += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\xc0\x00\x02\x01"
        s.sendto(bytes(r), addr)

def later_10000():
    while not os.path.exists("/tmp/open-10000"):
        time.sleep(0.5)
    tcp(10000, quiet)

for port, h in ((22, ssh), (80, http), (8080, quiet)):
    threading.Thread(target=tcp, args=(port, h), daemon=True).start()
threading.Thread(target=dns, daemon=True).start()
threading.Thread(target=later_10000, daemon=True).start()
print("bench ready", flush=True)
threading.Event().wait()
