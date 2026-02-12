import subprocess
import sys
import ipaddress

# STRICT WHITELIST
# We will NEVER block these ranges
WHITELIST_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("10.0.0.0/8"),       # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),    # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),   # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),   # Link-Local
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
]

def is_whitelisted(ip_str):
    """Check if IP is in the whitelist (Private/Local)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for net in WHITELIST_NETWORKS:
            if ip in net:
                return True
        return False
    except ValueError:
        return True # If it's not a valid IP (e.g. malformed), don't block it.

def block_ip(ip_str):
    """
    Block an IP using Windows Firewall (netsh).
    Requires Admin privileges.
    Returns: True if blocked, False if failed/whitelisted.
    """
    if is_whitelisted(ip_str):
        print(f"[FIREWALL] SKIP: {ip_str} is whitelisted (Private/Local).", file=sys.stderr)
        return False
        
    print(f"[FIREWALL] BLOCKING {ip_str}...", file=sys.stderr)
    
    # Command: netsh advfirewall firewall add rule name="Guardian Block <IP>" dir=in action=block remoteip=<IP>
    rule_name = f"Guardian Block {ip_str}"
    cmd = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in",
        "action=block",
        f"remoteip={ip_str}"
    ]
    
    try:
        # Check if rule already exists to avoid duplicates/errors
        check_cmd = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
        # If check succeeds (return code 0), rule exists.
        if subprocess.run(check_cmd, capture_output=True).returncode == 0:
            print(f"[FIREWALL] Rule for {ip_str} already exists.", file=sys.stderr)
            return "EXISTING"

        # Run Block Command
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[FIREWALL] SUCCESS: Blocked {ip_str}", file=sys.stderr)
            return "NEW"
        else:
            print(f"[FIREWALL] FAILED: {result.stderr.strip()}", file=sys.stderr)
            if "Run as administrator" in result.stderr:
                print("[FIREWALL] TIP: Rerun terminal as Administrator!", file=sys.stderr)
            return "FAILED"
            
    except Exception as e:
        print(f"[FIREWALL] ERROR: {e}", file=sys.stderr)
        return "FAILED"

def unblock_ip(ip_str):
    """
    Remove a blocking rule for an IP.
    """
    rule_name = f"Guardian Block {ip_str}"
    print(f"[FIREWALL] UNBLOCKING {ip_str}...", file=sys.stderr)
    
    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[FIREWALL] SUCCESS: Unblocked {ip_str}", file=sys.stderr)
            return True
        else:
            # If rule doesn't exist, it's technically a "success" for the user's intent
            if "No rules match" in result.stdout or "No rules match" in result.stderr:
                return True
            print(f"[FIREWALL] FAILED: {result.stderr.strip()}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"[FIREWALL] ERROR: {e}", file=sys.stderr)
        return False
