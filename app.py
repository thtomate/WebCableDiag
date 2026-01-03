import re
import time
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, request, redirect, url_for, flash
from netmiko import ConnectHandler
from cachetools import TTLCache

# Configuration
APP_HOST = "0.0.0.0"
APP_PORT = 5000
DEBUG = True
TDR_CACHE_TTL = 60  # seconds
INTERFACES_CACHE_TTL = 30  # seconds
MAX_WORKERS = 8

NETMIKO_ALLOWED_KEYS = {
    "device_type", "host", "username", "password", "secret", "allow_agent",
    "port", "verbose", "session_log", "timeout", "conn_timeout",
    "fast_cli", "global_delay_factor", "blocking_timeout", "ssh_config_file",
}

def sanitize_device_for_netmiko(device):
    """Return a new dict containing only keys Netmiko accepts."""
    sanitized = {}
    for k, v in device.items():
        if k in NETMIKO_ALLOWED_KEYS:
            sanitized[k] = v
    # ensure host exists (fallback to 'ip' if you used that)
    if "host" not in sanitized and "ip" in device:
        sanitized["host"] = device["ip"]
    return sanitized

app = Flask(__name__)
app.secret_key = "change_this_secret_change_in_prod"

# Load inventory with multiple sites
with open("inventory.yaml") as f:
    INVENTORY = yaml.safe_load(f)

SITES = INVENTORY.get("sites", [])

# Helper lookups
def get_site_by_name(site_name):
    for s in SITES:
        if s.get("name") == site_name:
            return s
    return None

def find_access_by_name(site_name, name):
    site = get_site_by_name(site_name)
    if not site:
        return None
    for sw in site.get("access_switches", []):
        if sw.get("name") == name:
            sw_copy = sw.copy()
            sw_copy["_site"] = {"name": site.get("name"), "description": site.get("description")}
            return sw_copy
    return None

# Caches
tdr_cache = TTLCache(maxsize=2048, ttl=TDR_CACHE_TTL)
mac_cache = TTLCache(maxsize=2048, ttl=60)
interfaces_cache = TTLCache(maxsize=1024, ttl=INTERFACES_CACHE_TTL)

executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

# --- SSH helpers --------------------------------------------------------------
def ssh_connect(device):
    """Create a ConnectHandler with a sanitized copy of device params."""
    defaults = INVENTORY.get("netmiko_defaults", {})
    device = {**defaults, **device}
    params = sanitize_device_for_netmiko(device)
    return ConnectHandler(**params)

def cache_key(prefix, *parts):
    return prefix + ":" + "|".join(parts)

def normalize_mac(mac):
    s = re.sub(r"[^0-9a-fA-F]", "", mac).lower()
    if len(s) != 12:
        raise ValueError("Ungültige MAC Adresse")
    return s[0:4] + "." + s[4:8] + "." + s[8:12]

# --- Interfaces retrieval and parsing ----------------------------------------
def get_interfaces_for_device(device):
    """
    Returns a list of interface dicts: {name, status, type}
    Uses caching to avoid frequent SSH calls.
    """
    key = cache_key("iflist", device.get("host"))
    if key in interfaces_cache:
        return interfaces_cache[key]

    conn = ssh_connect(device)
    try:
        out = conn.send_command("show interfaces status", delay_factor=1, use_textfsm=True)  # show int desc?
        print(out)
        # interfaces: list of {"name", "description", "status", "type"}
        interfaces = [
            {
                "name": entry.get("port"),
                "description": entry.get("name"),
                "status": entry.get("status"),
                "type": entry.get("type")
            }
            for entry in out
        ]
        # only store in cache if not empty as empty is probably an error
        if interfaces and interfaces != []:
            interfaces_cache[key] = interfaces
        return interfaces
    finally:
        conn.disconnect()

def find_mac_on_central_for_site(site_name, mac):
    key = cache_key("mac", site_name, mac)
    if key in mac_cache:
        return mac_cache[key]
    site = get_site_by_name(site_name)
    if not site:
        raise ValueError("Site nicht gefunden")
    central = site.get("central_switch")
    m_formatted = normalize_mac(mac)
    conn = ssh_connect(central)
    try:
        cmd = f"show mac address-table address {m_formatted}"
        out = conn.send_command(cmd)  # may use textfsm
        interface = None
        for line in out.splitlines():
            if m_formatted in line:
                parts = line.split()
                for token in reversed(parts):
                    if re.match(r"^(Gi|Fa|Te|Tw|Et|Ethernet|Po|Port-channel|Eth)\S*", token, re.IGNORECASE) or re.match(r"^[A-Za-z]+[0-9/]+$", token):
                        interface = token
                        break
                if interface:
                    break
        result = {"mac": m_formatted, "raw": out, "interface": interface, "site": site_name}
        mac_cache[key] = result
        return result
    finally:
        conn.disconnect()

def resolve_access_switch_from_interface_for_site(site_name, interface):
    site = get_site_by_name(site_name)
    central = site.get("central_switch")
    conn = ssh_connect(central)
    try:
        cmd = f"show cdp neighbors {interface} detail"  # TODO nexus support
        if "nxos" in central.get("device_type", ""):
            cmd = f"show cdp neighbors interface {interface} detail"
        out = conn.send_command(cmd)  # may use textfsm
        name = None
        ip = None
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Device ID:"):
                name = line.split("Device ID:")[1].strip()
            if "IP address:" in line:
                ip = line.split("IP address:")[1].strip()
        return {"cdp_name": name, "cdp_ip": ip, "raw": out, "site": site_name}
    finally:
        conn.disconnect()

def parse_tdr_output(out):
    parsed = {"raw": out, "pairs": []}
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    pair_re = re.compile(r".{0,25}Pair\s+([A-D])[:\-\s]*(.*)", re.IGNORECASE)
    len_re = re.compile(r"(\d+(\.\d+)?)(\s*\+\/\-\s*\d*)?\s*(m|meters|meter|m\.)", re.IGNORECASE)
    status_re = re.compile(r"(open|short|ok|normal|fault|not supported|unsupported|no tdr)", re.IGNORECASE)
    for line in lines:
        m = pair_re.match(line)
        if m:
            pair = m.group(1).upper()
            rest = m.group(2).strip()
            length = None
            status = None
            lm = len_re.search(rest)
            if lm:
                length = lm.group(1)
            sm = status_re.search(rest)
            if sm:
                status = sm.group(1).lower()
            parsed["pairs"].append({
                "pair": pair,
                "status": status,
                "length_m": length,
                "details": rest
            })
    if not parsed["pairs"]:
        for line in lines:
            lm = len_re.search(line)
            if lm:
                length = lm.group(1)
                parsed["pairs"].append({
                    "pair": None,
                    "status": None,
                    "length_m": length,
                    "details": line
                })
    if not parsed["pairs"]:
        parsed["note"] = "No parsed pair data; raw output provided"
    return parsed

def tdr_single_interface(device, interface):
    """
    Run TDR diagnostics on a single interface and fetch the results after a delay.
    """
    key = cache_key("tdr", device.get("host"), interface)
    if key in tdr_cache:
        return tdr_cache[key]
    
    conn = ssh_connect(device)
    try:
        conn.send_command("terminal length 0")
        # Start TDR diagnostics
        start_output = conn.send_command(
            f"test cable-diagnostics tdr interface {interface}",
            expect_string=r"#|>", delay_factor=1
        )
        if "Invalid input" in start_output or "Unknown command" in start_output or "Command not found" in start_output:
            parsed = {"raw": start_output, "error": "No valid TDR command on device"}
            tdr_cache[key] = parsed
            return parsed
        
        # Wait for TDR results to be ready
        time.sleep(10)  # Adjust delay as needed based on device behavior
        
        # Fetch TDR results
        result_output = conn.send_command(f"show cable-diagnostics tdr interface {interface}")
        print(result_output)
        parsed = parse_tdr_output(result_output)
        tdr_cache[key] = parsed
        return parsed
    finally:
        conn.disconnect()

def tdr_on_switch_async(device, interfaces):
    """TODO rework this AI shit"""
    futures = {executor.submit(tdr_single_interface, device, iface): iface for iface in interfaces}
    results = {}
    for fut in as_completed(futures):
        iface = futures[fut]
        try:
            res = fut.result()
        except Exception as e:
            res = {"raw": "", "error": str(e)}
        results[iface] = res
    return results

# --- Flask routes -------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", sites=SITES)

@app.route("/site/<site_name>", methods=["GET", "POST"])
def site_page(site_name):
    site = get_site_by_name(site_name)
    if not site:
        flash("Site nicht gefunden")
        return redirect(url_for("index"))
    access_list = site.get("access_switches", [])
    central = site.get("central_switch")
    if request.method == "POST":
        if "select_switch" in request.form:
            sw_name = request.form.get("access_switch")
            return redirect(url_for("switch_detail", site_name=site_name, name=sw_name))
        if "search_mac" in request.form:
            mac = request.form.get("mac")
            return redirect(url_for("search_mac_sitewide", site_name=site_name, mac=mac))
    return render_template("site.html", site=site, access_list=access_list, central=central)

@app.route("/site/<site_name>/switch/<name>", methods=["GET", "POST"])
def switch_detail(site_name, name):
    site = get_site_by_name(site_name)
    if not site:
        flash("Site nicht gefunden")
        return redirect(url_for("index"))
    device = find_access_by_name(site_name, name)
    if not device:
        flash("Switch nicht im Inventar für diese Site")
        return redirect(url_for("site_page", site_name=site_name))

    if request.method == "POST":
        # MAC address search
        if "search_mac" in request.form:
            mac = request.form.get("mac")
            return redirect(url_for("search_mac_switch", site_name=site_name, switch_name=name, mac=mac))
        
        if "run_tdr" in request.form:
            # TDR Run
            # collect interfaces from form: checkboxes named iface_<index> and possible free-text
            chosen = request.form.getlist("interfaces")
            free_text = request.form.get("interfaces_free", "")
            if free_text:
                extras = [s.strip() for s in free_text.split(",") if s.strip()]
                chosen.extend(extras)
            chosen = [c for c in chosen if c]
            if not chosen:
                flash("Keine Schnittstellen ausgewählt")
                return redirect(url_for("switch_detail", site_name=site_name, name=name))
            results = tdr_on_switch_async(device, chosen)
            return render_template("results.html", device=device, results=results, site=site)

    # GET: fetch interface list (cached)
    try:
        interfaces = get_interfaces_for_device(device)
    except Exception as e:
        interfaces = []
        flash(f"Fehler beim Abrufen der Interfaces: {e}")
    
    # show cached TDR results of this switch if available
    cached_results = [
        {
            "interface": iface.get("name"),
            "tdr": tdr_cache[cache_key("tdr", device.get("host"), iface.get("name"))]
        }
        for iface in interfaces
        if cache_key("tdr", device.get("host"), iface.get("name")) in tdr_cache
    ]

    return render_template("switch.html", device=device, site=site, interfaces=interfaces, highlighted_ifaces=request.args.get("highlighted_ifaces", "").split(","))

@app.route("/site/<site_name>/search_mac/<mac>", methods=["GET"])
def search_mac_sitewide(site_name, mac):
    try:
        mac_result = find_mac_on_central_for_site(site_name, mac)
    except ValueError as ve:
        flash("Ungültige MAC Adresse oder Site nicht vorhanden")
        print(ve)
        return redirect(url_for("site_page", site_name=site_name))
    interface = mac_result.get("interface")
    if not interface:
        flash("MAC nicht in MAC‑Tabelle des zentralen Switches gefunden")
        return redirect(url_for("site_page", site_name=site_name))
    neighbor = resolve_access_switch_from_interface_for_site(site_name, interface)
    mapped = None
    for sw in get_site_by_name(site_name).get("access_switches", []):
        if neighbor.get("cdp_ip") and sw.get("host") == neighbor.get("cdp_ip"):
            mapped = sw
            break
        if neighbor.get("cdp_name") and (sw.get("name").lower() == neighbor.get("cdp_name").lower() or sw.get("host").lower() == neighbor.get("cdp_name").lower()):
            mapped = sw
            break
    return render_template("mac_result.html", mac_search=mac_result, neighbor=neighbor, mapped=mapped, site=get_site_by_name(site_name))

@app.route("/site/<site_name>/switch/<switch_name>/search_mac/<mac>", methods=["GET"])
def search_mac_switch(site_name, switch_name, mac):
    device = find_access_by_name(site_name, switch_name)
    if not device:
        flash("Switch nicht im Inventar für diese Site")
        return redirect(url_for("site_page", site_name=site_name))
    
    m_formatted = normalize_mac(mac)
    conn = ssh_connect(device)
    try:
        cmd = f"show mac address-table address {m_formatted}"
        out = conn.send_command(cmd)
        interface = None
        for line in out.splitlines():
            if m_formatted in line:
                parts = line.split()
                for token in reversed(parts):
                    if re.match(r"^(Gi|Fa|Te|Tw|Et|Ethernet|Po|Port-channel|Eth)\S*", token, re.IGNORECASE) or re.match(r"^[A-Za-z]+[0-9/]+$", token):
                        interface = token
                        break
                if interface:
                    break
        mac_result = {"mac": m_formatted, "raw": out, "interface": interface, "site": site_name, "switch": switch_name}
    finally:
        conn.disconnect()
    if not interface:
        flash("MAC nicht in MAC‑Tabelle des Switches gefunden")
        return redirect(url_for("switch_detail", site_name=site_name, name=switch_name))
    else:
        flash(f"MAC {m_formatted} gefunden auf Schnittstelle {interface}. Ich versuche es dir schon zu markieren.")
        return redirect(url_for("switch_detail", site_name=site_name, name=switch_name, highlighted_ifaces=interface))



# Run
if __name__ == "__main__":
    app.run(host=APP_HOST, port=APP_PORT, debug=DEBUG)
