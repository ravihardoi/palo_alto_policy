"""
paloalto_policy_manager.py - Reads a list of requested firewall policies
from Excel and runs them through this pipeline for each row:

    Excel -> Resolve zones from routing -> Validate objects -> Check
    existing rules -> Check duplicate/shadowing -> Show proposed
    change -> DRY RUN -> Apply

You do NOT provide Source Zone / Destination Zone in the Excel sheet.
Instead, for every Source and Destination address you give it, the
script asks the firewall's own routing table (via a FIB lookup) which
interface that traffic would use, then looks up which zone that
interface belongs to - the same two steps ("test routing fib-lookup",
then "show interface ... | match Zone") a network engineer would do by
hand. See STEP 0 below for exactly how this works and its limits.

In plain terms: for every row, it figures out the Source/Destination
zones from routing, checks the values actually make sense, checks
whether a matching rule already exists (and if so just adds the new
Source address to it instead of duplicating), checks whether an
earlier rule would block/shadow the new one before it's ever reached,
prints exactly what it's about to do, and only actually changes
anything on the firewall if you've told it to.

WHAT THIS SCRIPT DOES NOT DO
-----------------------------
It does not look at traffic logs or try to figure out what's currently
being blocked in practice. Its "shadowing" check (see below) is a
config-level check against the existing rulebase, not a traffic-log
analysis - a deliberate scope limit to keep this predictable.

Zone resolution (STEP 0) is a routing-table lookup, not a guarantee -
see the limits called out in that section. If your network isn't
symmetric (the return path differs from the forward path), the zone
this script infers for an address may not match reality - review the
proposed change before applying.

ADDRESS NORMALIZATION (fixes duplicate rules for equivalent subnets)
------------------------------------------------------------------------
Any Source/Destination value written as an IP/CIDR is normalized to its
canonical network form before it's ever compared or stored - e.g.
"50.50.50.50/24" and "50.50.50.0/24" are the exact same /24 network
(one just has host bits set instead of zeroed), so both get normalized
to "50.50.50.0/24". Without this, the script would treat them as two
different addresses, fail to find the existing matching rule, and
create a redundant duplicate - which is exactly the bug this fixes.
This only touches values that parse as a plain IP or IP/CIDR - "any",
address ranges ("10.1.1.5-10.1.1.10"), and existing Address object/group
names are left exactly as you typed them. See normalize_address().

Source merging is also subnet-aware (see merge_source_addresses()): if
a rule already has a broader network and a narrower request comes in
that's already inside it, nothing is added (it's already covered); if a
broader network comes in later that now covers an existing narrower
entry, that narrower entry is replaced - so a rule's source list never
ends up with redundant overlapping entries like both 10.1.1.0/24 and
10.1.1.5/32.

DEFAULT-ROUTE EXCLUSION (never infers a zone from the default route)
------------------------------------------------------------------------
A FIB lookup ("test routing fib-lookup") returns whichever route is the
BEST match for an IP - and if nothing more specific exists, that's
legitimately the default route (0.0.0.0/0). A default route just means
"send this out to the internet/upstream somewhere" - it says nothing
about which zone that address actually belongs to, so treating a
default-route match the same as a real, specific route would mean
inferring a zone (and creating a policy against it) from essentially a
guess.

Before trusting a FIB-lookup match, STEP 0 now cross-checks the same
virtual router's real routing table ("show routing route") and confirms
the most specific route actually covering that IP has a prefix length
greater than 0. If the ONLY thing covering an address in a given virtual
router is the default route, that virtual router is excluded from zone
resolution entirely for that address - exactly as if it had no route at
all. If EVERY virtual router checked ends up in that state (no route, or
default-route-only), the row is marked "Could not implement - no
specific route found" and NO rule is created, even with apply on - the
same treatment as a genuine no-route case, and for the same reason: this
script would rather tell you it doesn't know than guess. Add a specific
route, or set "virtual_router" in the config and specify the zone
manually if you're confident, to get past this. See
get_virtual_router_routes() and most_specific_route_prefixlen().

TAG AUTO-CREATION
-------------------
PAN-OS rejects a rule whose Tag value doesn't reference an existing Tag
object (Objects > Tags) - you'd get an error like "tag 'MyTag' is not a
valid reference". If your Tag column has a value that doesn't already
exist as a Tag object on the firewall, this script creates it
automatically (only when "apply": true) instead of failing - the same
approach already used for bare-port Service values. A blank Tag cell is
untouched (no tag, which is perfectly valid). Tags are ONLY set when
creating a brand-new rule - merging a Source into an existing rule never
touches that rule's tag, so an existing rule's tag is never overwritten
or removed by a later row that happens to match it.

SETUP
-----
1. pip install pan-os-python openpyxl

2. Create paloalto_config.json next to this file. This is also where the
   Excel filename and run mode live now, so you can just double-click this
   script (or a .exe built from it) with NO command-line arguments at all -
   important if you're running it from IDLE's "Run Module", or packaging
   it into a .exe with PyInstaller, since neither of those passes
   command-line flags.

    {
      "hostname": "<firewall IP or FQDN>",
      "api_key": "<API key>",

      "excel_path": "requests.xlsx",
      "request_sheet": "Request",
      "implementation_sheet": "Implementation",
      "apply": false,
      "commit": false
    }

   No "virtual_router" key needed by default - the script checks EVERY
   virtual router on the firewall for each address and uses whichever
   one(s) actually have a route (see STEP 0 below). Only add
   "virtual_router": "<name>" if you want to FORCE a single specific one
   (e.g. to skip checking others, or because you know an address routes
   differently in different VRs and want a specific answer):

    {
      "hostname": "<firewall IP or FQDN>",
      "api_key": "<API key>",
      "virtual_router": "default",
      "excel_path": "requests.xlsx"
    }

   If you don't have an API key yet, you can instead put username/password
   and the SDK will generate the key for you on first connect:

    {
      "hostname": "<firewall IP or FQDN>",
      "username": "<admin username>",
      "password": "<admin password>",
      "excel_path": "requests.xlsx"
    }

   excel_path is relative to wherever this script (or the .exe) lives, so
   if requests.xlsx is in the same folder, just the filename is fine.

   apply / commit work exactly as before (see RUN MODES below) - just set
   as true/false in the config file instead of as command-line flags.
   If you DO run this from a terminal, --apply / --commit / --excel still
   work and simply override whatever the config file says, so you can
   keep apply/commit as false (safe default) in the file and only turn
   them on explicitly per run from the terminal if you want that instead.

PACKAGING AS A .EXE
--------------------
Once this behaves the way you want when run as "python paloalto_policy_manager.py"
with no arguments, you can package it with PyInstaller:

    pip install pyinstaller
    pyinstaller --onefile paloalto_policy_manager.py

The resulting .exe (in the dist folder) reads paloalto_config.json and
requests.xlsx from the SAME FOLDER the .exe is run from - keep all three
together, same as the layout described above. This is handled by
get_base_dir() near the top of the script: a naive "look next to this
file" approach breaks under PyInstaller, because a frozen .exe extracts
itself into a temporary folder at runtime and __file__ points there
instead of to the .exe's real location - get_base_dir() detects that
(via sys.frozen, which PyInstaller sets) and uses the .exe's actual
folder instead, so config/Excel lookups work the same whether you run
the .py directly or the packaged .exe.

3. Your Excel file needs a "Request" sheet (rename via --request-sheet if
   yours is called something else) with a header row containing these
   columns (order doesn't matter - the script reads by column name):

      Tag | Source | Destination | Destination Port | Application |
      Service | Action

   No Source Zone / Destination Zone columns - see STEP 0 below.

   NOTE on Destination Port vs Service: if you fill in Destination Port,
   the script builds the actual PAN-OS service from Destination Port +
   Service together - Service, if given, just supplies the protocol
   ("tcp" or "udp"; defaults to tcp if you don't say). E.g. Destination
   Port "443" with Service blank or "tcp" becomes tcp/443. If you leave
   Destination Port blank, the Service column works exactly like before
   (a bare port, "tcp/443", "any", "application-default", or an existing
   Service object name). This was my best guess at what having both
   columns was meant to do - tell me if you intended something else and
   I'll adjust build_raw_service_values(), which is where this lives.

   NOTE on "Application": if this column is missing, or a row leaves it
   blank, the script defaults to "any". If you type "application-default"
   here (an easy mistake - that keyword IS valid, but only in the Service
   field, meaning "use the standard port for whatever application is
   selected"), the script automatically substitutes "any" instead and
   notes that it did so - PAN-OS itself rejects "application-default" as
   an Application value.

   Source / Destination / Destination Port / Service / Application can
   each hold more than one value in a single cell - separate them with
   commas, e.g. "10.1.1.5, 10.1.1.6".

STEP 0 - RESOLVE ZONES FROM ROUTING
--------------------------------------
For every Source and Destination address in a row, the script:
    1. Turns the address into a single IP to look up (if it's a raw IP/
       CIDR it uses that; if it's an existing Address object, it uses
       that object's underlying IP; "any" is left as "any" and skipped -
       no lookup needed).
    2. Runs a FIB lookup to find which interface the firewall would
       route that IP through ("test routing fib-lookup ... ip <ip>") -
       against EVERY virtual router on the firewall by default (not just
       "default"), unless you've forced a single one via "virtual_router"
       in the config. If more than one VR has a route and they land on
       DIFFERENT zones, that's flagged as a problem rather than guessed
       at, same as the mixed-zone case below - set "virtual_router" in
       the config to pick one if that happens.
    3. Looks up which zone that interface belongs to
       ("show interface <name>").

    A route that turns out to be the DEFAULT route (0.0.0.0/0) is never
    treated as good enough to resolve a zone from - see DEFAULT-ROUTE
    EXCLUSION above. If a virtual router's only match for an address is
    its default route, that VR is treated the same as having no route at
    all for that address.

If a row has more than one Source (or Destination) address and they
resolve to DIFFERENT zones, that's flagged as a validation problem
("split into separate rows") rather than guessed at - a single security
rule can only have one set of zones, so mixed-zone requests need a
human decision, not a silent pick.

LIMITS of this step, worth knowing before you trust it blindly:
    - It can only resolve a single IP or an existing Address OBJECT
      (not an Address GROUP - groups can contain many differently-
      routed members, so those are flagged as unresolvable and need
      manual zone entry, currently not supported by this script).
    - It relies on your routing table reflecting reality. If routing is
      asymmetric, or a static route points somewhere unusual, the zone
      inferred here may not match the zone traffic actually arrives on
      in practice.
    - Checking multiple virtual routers means more API calls per new IP
      (one FIB lookup per VR, until/unless one finds a route) - results
      are cached per run so the same IP is never looked up twice, but a
      very large sheet with hundreds of distinct IPs on a firewall with
      many VRs will take a while. Set "virtual_router" in the config to
      skip checking the others if you already know which one applies.

STEP 1 - VALIDATE OBJECTS
---------------------------
Before touching the rulebase, each row is checked for:
    - Source / Destination addresses resolved to exactly one zone each
      (see STEP 0's limits above for when this fails)
    - Source / Destination entries look like a real IP/CIDR/range, OR
      match an existing Address object / Address group name, OR are the
      keyword "any"
    - Destination Port, if given, is numeric
    - Service entries that aren't "any", "application-default", or a
      bare port (which gets auto-converted - see STEP 3 below) are
      checked against existing Service objects on the firewall
    - Action is one of PAN-OS's real action keywords (allow/deny/drop/etc)
A row that fails validation is marked "Validation error" and skipped -
nothing is matched, created, or shadow-checked for that row.

STEP 2 - CHECK EXISTING RULES / STEP 3 - CHECK DUPLICATE-OR-SHADOWING
------------------------------------------------------------------------
An existing rule is considered "the same policy" as a requested row when
ALL of these match:
    - Source Zone (as resolved in STEP 0)
    - Destination Zone (as resolved in STEP 0)
    - Destination (exact same set, AFTER CIDR normalization - see above)
    - Service (exact same set - bare ports get converted first, see below)
    - Application (exact same set)
    - Action

Source is deliberately EXCLUDED from that match - that's the whole
point. If a match is found:
    - if every requested Source is already COVERED by that rule's
      existing sources - either an exact match after normalization, or
      contained within a broader network already there (e.g. a request
      for 10.1.1.5 when the rule already has 10.1.1.0/24) - it's a
      DUPLICATE, nothing to do, marked "Duplicate - already exists".
    - otherwise, the new Source(s) get merged into that existing rule's
      source list instead of creating a duplicate rule. Merging is
      subnet-aware (see merge_source_addresses()): a host address
      already covered by a broader network already in the rule is never
      added as a redundant second entry, and if a newly arriving Source
      is a BROADER network that now covers an existing narrower entry,
      that narrower entry is removed in favor of the broader one - so
      the source list never ends up with e.g. both 100.100.100.0/24 and
      100.100.100.50/32 sitting there redundantly.

If NO matching rule is found, before creating a new one the script checks
for SHADOWING: does an earlier rule in the current rulebase order already
cover this exact traffic with a DIFFERENT action (e.g. a broad "deny any"
sitting above would mean a new "allow" rule below it never actually
takes effect)? Address fields here are also compared after normalization,
and "covers" additionally treats a rule's broader network as covering a
requested narrower one WITHIN that same subnet (e.g. a rule for
10.1.1.0/24 covers a request for 10.1.1.5) - it does NOT do full
cross-subnet overlap math beyond simple containment, and still treats
"any" as covering everything. If shadowing is detected, the row is
marked "Shadow conflict - not created" and the rule is NOT created even
if apply is on - this needs a human to look at rule order and decide
what to do.

If you want a looser or stricter definition of "same policy" or
"shadowing", it's all in one place: the rule_matches_request() and
check_shadowing() functions below - short, plain if-checks, easy to
adjust.

STEP 4 - SHOW PROPOSED CHANGE
-------------------------------
Whatever the outcome (validation error, duplicate, merge, shadow
conflict, new rule, or "could not implement - no route found" when
STEP 0 can't find a route for the Source or Destination on any checked
virtual router), the script prints exactly what it found / would do for
that row BEFORE doing anything, and writes the same into the
Implementation sheet's Outcome/Details columns - so a dry run gives you
a full preview to review before you ever set apply to true.

STEP 5 - DRY RUN / APPLY
---------------------------
By default this script is a DRY RUN: it connects to the firewall, runs
steps 1-4 above, and writes the results to the Implementation sheet - but
makes no changes on the firewall.

Set "apply": true in paloalto_config.json (or pass --apply from a
terminal) to actually create the new rules / update existing rules /
create service objects on the firewall (this stages changes in the
candidate config - NOT yet live).

Set "commit": true as well (or pass --commit) to also commit the
candidate config, making the changes live.

BATCH SIMULATION IN DRY RUN: if two rows in the SAME sheet describe the
same policy (e.g. row 2 and row 6 both resolve to the same normalized
Source/Destination/Service/Application/Action), the dry-run preview
correctly shows only the FIRST one as "Created new rule" and the second
as "Duplicate - already exists" (or "Merged", if only the Source
differs) - it does not need "apply": true to see this. Rows are always
compared against everything proposed so far in the same run, in
sheet order, not just against what's already live on the firewall.
"""

import re
import sys
import json
import argparse
import ipaddress
from pathlib import Path
from datetime import datetime

import openpyxl
from panos.firewall import Firewall
from panos.policies import Rulebase, SecurityRule
from panos.objects import ServiceObject, AddressObject, AddressGroup, Tag
from panos.network import Zone, VirtualRouter


def get_base_dir() -> Path:
    """The folder this script (or the packaged .exe) actually lives in -
    used to find paloalto_config.json and, by default, requests.xlsx.

    This matters specifically for PyInstaller .exe builds: when frozen,
    PyInstaller extracts everything into a TEMPORARY folder at runtime
    (something like ...\\AppData\\Local\\Temp\\_MEIxxxxxx\\) and __file__
    points THERE, not to wherever the .exe actually sits on disk - even
    though the .exe, config, and Excel file are all sitting together in
    the same real folder. sys.frozen is set by PyInstaller's bootloader,
    so this checks for that and uses sys.executable's folder instead in
    that case. Plain "python paloalto_policy_manager.py" is unaffected -
    sys.frozen isn't set, so it still uses __file__ as before."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


CONFIG_FILE = get_base_dir() / "paloalto_config.json"

REQUEST_COLUMNS = [
    "Tag", "Source", "Destination", "Destination Port", "Application", "Service", "Action",
]

# What "no traffic log analysis" the module docstring promises is unrelated
# to this - this is just a whitelist of PAN-OS security rule actions, used
# to catch typos in the Action column during validation.
VALID_ACTIONS = {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}

# A loose IP / CIDR / range matcher - good enough to tell "this looks like
# a raw address" apart from "this is probably an object name". Not a full
# IP validator (won't catch e.g. 999.999.999.999) - it's a sanity check,
# not a guarantee.
IP_LIKE_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){0,3}(/\d{1,2})?(-\d{1,3}(\.\d{1,3}){0,3})?$")


def normalize_address(value: str) -> str:
    """Normalizes an IP/CIDR value to its canonical network form, so two
    differently-written values for the SAME network compare equal - e.g.
    '50.50.50.50/24' and '50.50.50.0/24' are literally the same /24
    network (one just has host bits set), so both become '50.50.50.0/24'.

    Without this, the script would treat them as different addresses,
    never find the existing matching rule, and create a redundant
    duplicate - this function is the fix for exactly that bug.

    Only touches values that parse as a plain IP or IP/CIDR. "any",
    address ranges ("10.1.1.5-10.1.1.10"), and Address object/group
    names are returned unchanged - ranges aren't handled by Python's
    ipaddress module and object/group names aren't IPs at all."""
    text = value.strip()
    if text.lower() == "any":
        return "any"
    if "/" in text and "-" not in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return text  # not a valid CIDR - leave as-is, validate_row() will flag it
    return text


def normalize_address_list(values: list) -> list:
    return [normalize_address(v) for v in values]


# --- Config / connection -------------------------------------------------

def load_config() -> dict:
    if not CONFIG_FILE.exists():
        print(f"ERROR: config file not found at {CONFIG_FILE}. See the SETUP notes at the top of this script.")
        sys.exit(1)
    config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    if not config.get("hostname"):
        print(f"ERROR: {CONFIG_FILE} is missing 'hostname'.")
        sys.exit(1)
    if not config.get("api_key") and not (config.get("username") and config.get("password")):
        print(f"ERROR: {CONFIG_FILE} needs either 'api_key', or both 'username' and 'password'.")
        sys.exit(1)
    # Defaults for the optional run-mode settings, so an older config file
    # without these keys still works.
    config.setdefault("excel_path", "requests.xlsx")
    config.setdefault("request_sheet", "Request")
    config.setdefault("implementation_sheet", "Implementation")
    config.setdefault("apply", False)
    config.setdefault("commit", False)
    config.setdefault("virtual_router", None)  # None = check every virtual router
    return config


def connect_to_firewall(config: dict):
    """Connects to the firewall and pulls back everything the validation,
    zone-resolution, and matching steps need: existing security rules,
    existing Service objects, existing Tag objects, existing zones,
    existing Address objects/groups (plus their IP values, for zone
    resolution), and the virtual router(s) to run routing lookups against.
    Returns (firewall_object, rulebase_object, list_of_existing_rules,
    dict_of_existing_services_by_name, set_of_known_tag_names,
    set_of_zone_names, set_of_known_address_names,
    dict_of_address_object_values, list_of_virtual_router_names_to_check)."""
    if config.get("api_key"):
        fw = Firewall(config["hostname"], api_key=config["api_key"])
    else:
        fw = Firewall(config["hostname"], config["username"], config["password"])

    rulebase = fw.add(Rulebase())
    existing_rules = SecurityRule.refreshall(rulebase)

    existing_services = ServiceObject.refreshall(fw)
    existing_services_by_name = {s.name: s for s in existing_services}

    # PAN-OS requires a rule's Tag values to reference Tag objects that
    # already exist - a bare string that isn't a real Tag object fails
    # with "tag '<name>' is not a valid reference" when the rule is
    # pushed. This is fetched so resolve_tags() can auto-create any
    # missing ones, the same pattern already used for Service objects.
    known_tag_names = {t.name for t in Tag.refreshall(fw)}

    zone_names = {z.name for z in Zone.refreshall(fw)}

    address_objects = AddressObject.refreshall(fw)
    address_groups = AddressGroup.refreshall(fw)
    known_address_names = {a.name for a in address_objects} | {g.name for g in address_groups}
    # name -> underlying IP value, used to resolve an Address object to an
    # actual IP for the routing/FIB lookup in STEP 0. Address groups are
    # NOT included here on purpose - see the module docstring's STEP 0
    # limits section for why.
    address_object_values = {a.name: a.value for a in address_objects}

    all_virtual_router_names = [vr.name for vr in VirtualRouter.refreshall(fw)]
    if not all_virtual_router_names:
        print("ERROR: no virtual routers found on this firewall - can't do routing-based zone lookups.")
        sys.exit(1)

    # "virtual_router" in config is now OPTIONAL and only needed to force a
    # SINGLE virtual router. Leave it unset (the default) and the script
    # checks EVERY virtual router on the firewall for each address, which
    # is what you want on a box with more than one VR - see STEP 0 in the
    # module docstring for how it handles an address that routes
    # differently depending on which VR is checked.
    forced_virtual_router = config.get("virtual_router")
    if forced_virtual_router:
        if forced_virtual_router not in all_virtual_router_names:
            print(f"ERROR: virtual_router '{forced_virtual_router}' not found on the firewall. Available: {all_virtual_router_names}")
            sys.exit(1)
        virtual_routers_to_check = [forced_virtual_router]
    else:
        virtual_routers_to_check = all_virtual_router_names

    return fw, rulebase, existing_rules, existing_services_by_name, known_tag_names, zone_names, known_address_names, address_object_values, virtual_routers_to_check


# --- STEP 0: Resolving zones from the routing table -----------------------
#
# This is the auto-detection feature: instead of you telling the script
# which zone a Source/Destination is in, it asks the firewall's own
# routing table. Same two commands a network engineer would run by hand:
#   1. "test routing fib-lookup ... ip <ip>"   -> which interface?
#   2. "show interface <name>"                 -> which zone is that interface in?
# See the module docstring's STEP 0 section for the full explanation and
# its limits (address groups, asymmetric routing, etc).

def get_ip_for_lookup(value: str, address_object_values: dict):
    """Turns one Source/Destination cell value into a single IP suitable
    for a FIB lookup. Returns (ip_or_None, error_or_None):
        ("any", None)      - the keyword "any" - no lookup needed
        ("1.2.3.4", None)  - a real IP to look up
        (None, "reason")   - couldn't turn this into a single IP"""
    text = value.strip()
    if text.lower() == "any":
        return ("any", None)

    if IP_LIKE_PATTERN.match(text):
        # Strip a /mask or an -end-of-range if present - the FIB lookup
        # needs a single address, not a whole subnet or range. Using the
        # first/network address is a reasonable stand-in for "which zone
        # is this in", since a whole subnet normally lives behind one
        # interface anyway.
        base = text.split("/")[0].split("-")[0]
        return (base, None)

    if text in address_object_values:
        object_value = address_object_values.get(text)
        if not object_value:
            return (None, f"Address object '{text}' has no value set")
        base = str(object_value).split("/")[0].split("-")[0]
        return (base, None)

    # Not a raw IP and not a known Address object - probably an Address
    # GROUP (which can have many differently-routed members) or a typo.
    # Either way we can't pick a single IP to look up automatically.
    return (None, f"'{text}' is an Address group or unknown object - can't auto-resolve its zone, specify manually")


def fib_lookup_interface(fw, ip: str, virtual_router: str):
    """Asks the firewall which interface it would route this IP through.
    Returns the interface name, or None if there's no route."""
    cmd = f"<test><routing><fib-lookup><virtual-router>{virtual_router}</virtual-router><ip>{ip}</ip></fib-lookup></routing></test>"
    try:
        response = fw.op(cmd, cmd_xml=False)
    except Exception as e:
        raise RuntimeError(f"FIB lookup for {ip} failed: {e}")
    interface_elem = response.find("./result/interface")
    if interface_elem is None or not interface_elem.text:
        return None
    return interface_elem.text.strip()


def get_zone_for_interface(fw, interface_name: str, interface_zone_cache: dict):
    """Looks up which zone an interface belongs to, caching results so
    the same interface is never queried twice in one run."""
    if interface_name in interface_zone_cache:
        return interface_zone_cache[interface_name]
    cmd = f"<show><interface>{interface_name}</interface></show>"
    try:
        response = fw.op(cmd, cmd_xml=False)
    except Exception as e:
        raise RuntimeError(f"'show interface {interface_name}' failed: {e}")
    zone_elem = response.find("./result/ifnet/zone")
    zone = zone_elem.text.strip() if zone_elem is not None and zone_elem.text else None
    interface_zone_cache[interface_name] = zone
    return zone


def get_virtual_router_routes(fw, virtual_router: str, route_cache: dict):
    """Fetches every route in one virtual router's routing table
    ("show routing route"), caching the result so each VR is only
    queried once per run. Used ONLY to check whether a FIB-lookup match
    was via a specific route or via the default route - see
    most_specific_route_prefixlen() and the DEFAULT-ROUTE EXCLUSION note
    in the module docstring for why that distinction matters.

    Returns a list of ipaddress network objects (one per route entry
    whose destination parses as a plain IP/CIDR). Assumes the standard
    PAN-OS 'show routing route' XML shape (<result><entry><destination>
    ...). If your PAN-OS version's output differs, this will just find
    no routes and get_zone_for_value() falls back to trusting the FIB
    lookup outright, same as before this fix - it never blocks a row on
    account of this call failing."""
    if virtual_router in route_cache:
        return route_cache[virtual_router]
    cmd = f"<show><routing><route><virtual-router>{virtual_router}</virtual-router></route></routing></show>"
    try:
        response = fw.op(cmd, cmd_xml=False)
    except Exception as e:
        raise RuntimeError(f"'show routing route' for {virtual_router} failed: {e}")
    routes = []
    for entry in response.findall("./result/entry"):
        dest_elem = entry.find("destination")
        if dest_elem is None or not dest_elem.text:
            continue
        try:
            routes.append(ipaddress.ip_network(dest_elem.text.strip(), strict=False))
        except ValueError:
            continue  # not a plain IP/CIDR destination - skip it, doesn't affect the check below
    route_cache[virtual_router] = routes
    return routes


def most_specific_route_prefixlen(routes: list, ip: str):
    """Returns the prefix length of the MOST SPECIFIC route in `routes`
    that actually contains this IP, or None if nothing in the table
    covers it. A return value of 0 means the only thing covering this IP
    is a default route (0.0.0.0/0 or ::/0) - see the caller for what
    that means for zone resolution."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    matching = [net for net in routes if address in net]
    if not matching:
        return None
    return max(net.prefixlen for net in matching)


def resolve_zone_for_value(fw, value: str, virtual_routers_to_check: list, address_object_values: dict, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict):
    """Resolves ONE Source/Destination cell value down to a single zone
    name by checking EVERY virtual router in virtual_routers_to_check
    (unless "virtual_router" was set in the config to force just one) and
    seeing which one(s) actually have a SPECIFIC route to it.
    Returns (zone_or_None, error_or_None)."""
    ip, error = get_ip_for_lookup(value, address_object_values)
    if error:
        return (None, error)
    if ip == "any":
        return ("any", None)

    if ip in ip_zone_cache:
        return ip_zone_cache[ip]

    # Check every virtual router - a route might only exist in one of
    # them, or (less commonly) the same subnet might be reachable via more
    # than one VR. zone_by_vr collects whichever VRs actually found a
    # SPECIFIC route (see below); default_route_only_vrs tracks any VR
    # where the ONLY thing that matched was the default route, purely so
    # the error message can say so plainly if nothing better is found.
    zone_by_vr = {}
    default_route_only_vrs = []
    for vr in virtual_routers_to_check:
        # A FIB lookup ("test routing fib-lookup") returns whichever route
        # is the BEST match for this IP - and that can legitimately be the
        # default route (0.0.0.0/0) if nothing more specific exists. A
        # default route just means "send it somewhere upstream" - it says
        # nothing about which zone this address actually belongs to, so a
        # zone must never be inferred from it. This checks the VR's real
        # routing table first and skips the VR entirely if the default
        # route is all that covers this IP.
        try:
            routes = get_virtual_router_routes(fw, vr, route_cache)
        except RuntimeError:
            routes = None  # couldn't read the routing table - fall back to trusting the FIB lookup below, as before this check existed
        if routes is not None:
            prefixlen = most_specific_route_prefixlen(routes, ip)
            if prefixlen == 0:
                default_route_only_vrs.append(vr)
                continue
        try:
            interface_name = fib_lookup_interface(fw, ip, vr)
        except RuntimeError:
            continue  # this VR errored on the lookup - treat as "no route here" and keep checking the others
        if interface_name is None:
            continue
        try:
            zone = get_zone_for_interface(fw, interface_name, interface_zone_cache)
        except RuntimeError:
            continue
        if zone:
            zone_by_vr[vr] = zone

    if not zone_by_vr:
        if default_route_only_vrs:
            result = (None, f"{value} ({ip}) only matches the DEFAULT route in {', '.join(default_route_only_vrs)} - not specific enough to confidently resolve a zone; add a specific route or specify the zone manually")
        else:
            result = (None, f"no route found for {value} ({ip}) in any virtual router checked ({', '.join(virtual_routers_to_check)})")
        ip_zone_cache[ip] = result
        return result

    distinct_zones = set(zone_by_vr.values())
    if len(distinct_zones) > 1:
        breakdown = ", ".join(f"{vr}->{zone}" for vr, zone in zone_by_vr.items())
        result = (None, f"{value} ({ip}) routes to different zones depending on virtual router ({breakdown}) - set \"virtual_router\" in paloalto_config.json to pick one")
        ip_zone_cache[ip] = result
        return result

    result = (distinct_zones.pop(), None)
    ip_zone_cache[ip] = result
    return result


def resolve_zone_for_list(fw, values: list, virtual_routers_to_check: list, address_object_values: dict, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict):
    """Resolves a whole Source or Destination cell (which may have
    multiple comma-separated values) down to a single zone. Returns
    (zone_or_None, list_of_problem_strings). If the values resolve to
    more than one distinct zone, that's reported as a problem rather
    than guessed at - see the module docstring's STEP 0 section."""
    zones_found = set()
    problems = []

    for value in values:
        zone, error = resolve_zone_for_value(fw, value, virtual_routers_to_check, address_object_values, interface_zone_cache, ip_zone_cache, route_cache)
        if error:
            problems.append(error)
        else:
            zones_found.add(zone)

    if problems:
        return (None, problems)
    if len(zones_found) > 1:
        return (None, [f"resolves to multiple different zones {sorted(zones_found)} - split into separate rows"])
    if not zones_found:
        return (None, ["no addresses to resolve a zone from"])
    return (zones_found.pop(), [])


# --- Resolving Service cell values into valid PAN-OS service names --------
#
# PAN-OS security rules can't take a raw port number like "443" in the
# Service field - it has to be either the keyword "any", the keyword
# "application-default", or the name of an existing Service object
# (built-in ones like "service-https", or a custom one). If your Excel
# cell has a bare port number, this section auto-creates a small Service
# object for it (e.g. "svc-tcp-443") so you don't have to go create one
# by hand in the GUI first.
#
# Accepted formats in the Service column:
#   any                  -> used as-is
#   application-default  -> used as-is
#   443                  -> becomes a tcp/443 object named "svc-tcp-443"
#   tcp/443               -> same as above, explicit protocol
#   udp/53                -> becomes a udp/53 object named "svc-udp-53"
#   service-https          -> assumed to already be a real object name, used as-is

PORT_PATTERN = re.compile(r"^(tcp|udp)?[/\s]?(\d+)$", re.IGNORECASE)


def parse_service_entry(raw_value: str):
    """Figures out what kind of Service entry this is. Returns one of:
        ("keyword", "any")
        ("keyword", "application-default")
        ("port", protocol, port)          - a bare port that needs an object
        ("name", raw_value)               - assumed to already exist on the firewall
    """
    text = raw_value.strip()
    if text.lower() in ("any", "application-default"):
        return ("keyword", text.lower())

    match = PORT_PATTERN.match(text)
    if match:
        protocol = (match.group(1) or "tcp").lower()  # bare port number defaults to tcp
        port = match.group(2)
        return ("port", protocol, port)

    return ("name", text)


def resolve_service_names(raw_service_values: list, existing_services_by_name: dict, taken_service_names: set, fw, apply_changes: bool):
    """Turns the Service column's raw values into a list of names that are
    actually valid to put on a security rule, creating a small Service
    object for any bare port numbers it finds along the way.
    Returns (resolved_names, notes) - notes is a list of human-readable
    strings describing anything that was created, for the results sheet."""
    resolved_names = []
    notes = []

    for raw_value in raw_service_values:
        kind, *rest = parse_service_entry(raw_value)

        if kind == "keyword":
            resolved_names.append(rest[0])
            continue

        if kind == "name":
            resolved_names.append(rest[0])
            continue

        # kind == "port"
        protocol, port = rest
        object_name = f"svc-{protocol}-{port}"
        resolved_names.append(object_name)

        if object_name in existing_services_by_name or object_name in taken_service_names:
            continue  # already exists on the firewall, or already queued to be created this run

        taken_service_names.add(object_name)
        notes.append(f"service object '{object_name}' ({protocol}/{port})")
        if apply_changes:
            new_service = ServiceObject(name=object_name, protocol=protocol, destination_port=port)
            fw.add(new_service)
            new_service.create()

    return resolved_names, notes


# --- Resolving Tag cell values into valid PAN-OS tag references ------------
#
# PAN-OS requires a security rule's Tag values to reference Tag objects
# that already exist (Objects > Tags in the GUI) - a plain string that
# isn't a real Tag object fails with "tag '<name>' is not a valid
# reference" when the rule is pushed. This auto-creates any tag that
# doesn't exist yet, the same way resolve_service_names() does for
# bare ports. Blank Tag cells are simply skipped - no tag is a valid,
# unremarkable choice, and existing rules being merged into never have
# their tag touched at all (see process_request - merging only ever
# updates a rule's source list, nothing else).

def resolve_tags(raw_tag_values: list, known_tag_names: set, taken_tag_names: set, fw, apply_changes: bool):
    """Returns (tag_names, notes) - tag_names is just raw_tag_values
    passed through unchanged (a Tag object's name IS the tag string,
    no transformation needed), notes describes any Tag objects that
    needed to be created."""
    notes = []
    for tag_name in raw_tag_values:
        if tag_name in known_tag_names or tag_name in taken_tag_names:
            continue  # already exists on the firewall, or already queued to be created this run
        taken_tag_names.add(tag_name)
        notes.append(f"tag '{tag_name}'")
        if apply_changes:
            new_tag = Tag(name=tag_name)
            fw.add(new_tag)
            new_tag.create()
    return raw_tag_values, notes


def build_raw_service_values(service_cell, dest_port_cell) -> list:
    """Combines the Service and Destination Port columns into the list of
    raw values resolve_service_names() expects.

    My best-guess interpretation of having both columns (documented in
    the module docstring too - adjust here if it's wrong): if Destination
    Port has a value, it's the authoritative port number(s), and Service
    (if given) just supplies the protocol - "tcp" or "udp", paired up by
    position, defaulting to tcp. Any Service entries beyond how many
    ports you gave are kept as-is (so you can still mix in "any" or a
    named object alongside explicit ports). If Destination Port is
    empty, Service works exactly like before (bare port, "tcp/443",
    "any", "application-default", or an object name)."""
    ports = split_values(dest_port_cell)
    services = split_values(service_cell)

    if not ports:
        return services

    combined = []
    for i, port in enumerate(ports):
        protocol = "tcp"
        if i < len(services) and services[i].lower() in ("tcp", "udp"):
            protocol = services[i].lower()
        combined.append(f"{protocol}/{port}")

    if len(services) > len(ports):
        combined.extend(services[len(ports):])

    return combined


# --- Reading the request sheet -------------------------------------------

def split_values(cell_value) -> list:
    """Splits a comma-separated cell into a clean list of strings.
    e.g. '10.1.1.5, 10.1.1.6' -> ['10.1.1.5', '10.1.1.6']"""
    if cell_value is None:
        return []
    text = str(cell_value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def read_requests(excel_path: Path, sheet_name: str) -> list:
    """Reads the request sheet into a list of plain dicts, one per row,
    keyed by the column headers in REQUEST_COLUMNS."""
    wb = openpyxl.load_workbook(excel_path, data_only=True)
    if sheet_name not in wb.sheetnames:
        print(f"ERROR: sheet '{sheet_name}' not found in {excel_path}. Sheets present: {wb.sheetnames}")
        sys.exit(1)
    ws = wb[sheet_name]

    header_row = [cell.value for cell in ws[1]]
    rows = []
    for row_cells in ws.iter_rows(min_row=2, values_only=True):
        row_dict = dict(zip(header_row, row_cells))
        # skip fully blank rows
        if all(v is None or str(v).strip() == "" for v in row_dict.values()):
            continue
        rows.append(row_dict)
    return rows


# --- STEP 1: Validating objects -------------------------------------------

def looks_like_address(value: str, known_address_names: set) -> bool:
    """True if value is 'any', looks like a raw IP/CIDR/range, or matches
    an existing Address object/group name on the firewall."""
    if value.lower() == "any":
        return True
    if IP_LIKE_PATTERN.match(value):
        return True
    return value in known_address_names


def validate_row(req: dict, raw_service_values: list, known_address_names: set, existing_services_by_name: dict) -> list:
    """Checks one request row for obviously bad values before we try to
    do anything with it on the firewall. Returns a list of problem
    strings - empty list means the row looks fine.

    Zone resolution (STEP 0) runs separately in process_request() and
    adds its own problems to this same list - see there for how the two
    fit together."""
    problems = []

    source_addrs = split_values(req.get("Source"))
    dest_addrs = split_values(req.get("Destination"))
    if not source_addrs:
        problems.append("Source is empty")
    if not dest_addrs:
        problems.append("Destination is empty")
    for addr in source_addrs + dest_addrs:
        if not looks_like_address(addr, known_address_names):
            problems.append(f"'{addr}' doesn't look like a valid IP/CIDR and isn't a known Address object")

    dest_ports = split_values(req.get("Destination Port"))
    for port in dest_ports:
        if not port.isdigit():
            problems.append(f"Destination Port '{port}' isn't a number")

    if not raw_service_values:
        problems.append("Service (or Destination Port) is empty")
    for value in raw_service_values:
        kind, *_ = parse_service_entry(value)
        if kind == "name" and value not in existing_services_by_name:
            problems.append(f"service '{value}' isn't a bare port and isn't a known Service object on the firewall")

    action = str(req.get("Action") or "").strip().lower()
    if not action:
        problems.append("Action is empty")
    elif action not in VALID_ACTIONS:
        problems.append(f"Action '{action}' isn't a valid PAN-OS action ({', '.join(sorted(VALID_ACTIONS))})")

    return problems


# --- Matching an existing rule --------------------------------------------

def rule_matches_request(rule, req: dict, resolved_service_names: list, req_application_list: list, req_source_zone: str, req_dest_zone: str, req_dest_addr: set) -> bool:
    """This is the 'is this the same policy' check. See the module
    docstring above for what's included and why. Edit this function if
    you want a different definition of 'same policy'.

    resolved_service_names comes from resolve_service_names() - already
    turned into real service-object names / keywords, not the raw Excel
    text, so this compares like-for-like against rule.service.
    req_source_zone / req_dest_zone come from STEP 0's routing-based
    resolution, not from the Excel sheet - there's no Zone column anymore.
    req_dest_addr is ALREADY NORMALIZED (see normalize_address()) - the
    rule's own destination values are normalized here too, so this
    compares like-for-like regardless of how either side originally
    wrote out an equivalent CIDR."""
    req_service = set(resolved_service_names)
    req_application = set(req_application_list)
    req_action = str(req.get("Action") or "").strip().lower()

    rule_source_zone = set(rule.fromzone or [])
    rule_dest_zone = set(rule.tozone or [])
    rule_dest_addr = set(normalize_address_list(rule.destination or []))
    rule_service = set(rule.service or [])
    rule_application = set(rule.application or [])
    rule_action = (rule.action or "").strip().lower()

    return (
        rule_source_zone == {req_source_zone}
        and rule_dest_zone == {req_dest_zone}
        and rule_dest_addr == req_dest_addr
        and rule_service == req_service
        and rule_application == req_application
        and rule_action == req_action
    )


def find_matching_rule(existing_rules: list, req: dict, resolved_service_names: list, req_application_list: list, req_source_zone: str, req_dest_zone: str, req_dest_addr: set):
    for rule in existing_rules:
        if rule_matches_request(rule, req, resolved_service_names, req_application_list, req_source_zone, req_dest_zone, req_dest_addr):
            return rule
    return None


# --- STEP 3 (no-match branch): checking for shadowing ----------------------

def covers(rule_field_values, req_values: set) -> bool:
    """True if an existing rule's field would 'cover' everything the new
    request needs on that same field - either the rule says 'any' (or is
    empty, which PAN-OS treats as 'any'), or every requested value is
    already inside the rule's set. Plain string/exact-match version, used
    for zones/service/application. For addresses, see covers_addresses()
    below, which additionally understands subnet containment."""
    rule_set = set(rule_field_values or [])
    if not rule_set or "any" in rule_set:
        return True
    return req_values.issubset(rule_set)


def covers_addresses(rule_field_values, req_values: set) -> bool:
    """Like covers(), but for Source/Destination fields specifically -
    understands that a rule for a broader network covers a request for a
    narrower one inside it (e.g. a rule with 10.1.1.0/24 covers a request
    for 10.1.1.5), not just an exact/any match. Both sides are normalized
    first (see normalize_address()) so equivalent CIDR notations compare
    correctly. This still isn't full cross-subnet overlap math - it's
    containment, which covers the common real-world case."""
    rule_values = normalize_address_list(rule_field_values or [])
    rule_set = set(rule_values)
    if not rule_set or "any" in rule_set:
        return True
    if req_values.issubset(rule_set):
        return True
    # Containment check: does every requested value fall inside some
    # network already in the rule? Falls back to plain string equality
    # for anything that isn't a parseable IP/CIDR (object names, ranges).
    for req_value in req_values:
        contained = False
        try:
            req_network = ipaddress.ip_network(req_value, strict=False)
        except ValueError:
            req_network = None
        for rule_value in rule_set:
            if req_value == rule_value:
                contained = True
                break
            if req_network is not None:
                try:
                    rule_network = ipaddress.ip_network(rule_value, strict=False)
                except ValueError:
                    continue
                if req_network.subnet_of(rule_network):
                    contained = True
                    break
        if not contained:
            return False
    return True


def _as_network_or_none(value: str):
    """Tries to parse a value as an IP network. Returns None for 'any',
    address ranges, object/group names, or anything else that isn't a
    plain IP/CIDR - callers fall back to exact string comparison for those."""
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def merge_source_addresses(current_sources: list, new_sources: list):
    """Combines new Source address(es) into an existing rule's source
    list, understanding subnet containment - this is the fix for a real
    bug: without it, adding a host address (e.g. 100.100.100.50/32) to a
    rule that already has the containing network (100.100.100.0/24)
    would add it as a REDUNDANT second entry instead of recognizing it's
    already covered. It also works the other way: if the new value is a
    BROADER network that now covers an existing narrower entry, that
    narrower entry is removed in favor of the broader one, keeping the
    source list as small and non-redundant as possible.

    Returns (merged_list, list_of_change_descriptions) - an empty list of
    descriptions means nothing needed to change (already fully covered)."""
    merged = list(current_sources)
    changes = []

    for new_value in new_sources:
        if new_value in merged:
            continue  # exact duplicate already present, nothing to do

        new_network = _as_network_or_none(new_value)

        if new_network is not None:
            already_covered_by = None
            for existing in merged:
                existing_network = _as_network_or_none(existing)
                if existing_network is None:
                    continue
                try:
                    if new_network.subnet_of(existing_network):
                        already_covered_by = existing
                        break
                except TypeError:
                    continue  # mismatched IP versions - not comparable, skip
            if already_covered_by is not None:
                changes.append(f"'{new_value}' already covered by existing '{already_covered_by}' - not added")
                continue

            redundant = []
            for existing in merged:
                existing_network = _as_network_or_none(existing)
                if existing_network is None:
                    continue
                try:
                    if existing_network.subnet_of(new_network) and existing != new_value:
                        redundant.append(existing)
                except TypeError:
                    continue
            for r in redundant:
                merged.remove(r)
                changes.append(f"removed '{r}' - now covered by broader '{new_value}'")

        merged.append(new_value)
        changes.append(f"added '{new_value}'")

    return merged, changes


def check_shadowing(existing_rules: list, req: dict, resolved_service_names: list, req_application_list: list, req_source_zone: str, req_dest_zone: str, req_source_addr: set, req_dest_addr: set):
    """Looks for an existing rule that would match all of this new
    request's traffic but with a DIFFERENT action - meaning if we add a
    new rule below it, the new rule would never actually be reached.
    req_source_addr / req_dest_addr are already normalized (see
    normalize_address()). Returns the shadowing rule if found, else None."""
    req_service = set(resolved_service_names)
    req_application = set(req_application_list)
    req_action = str(req.get("Action") or "").strip().lower()

    for rule in existing_rules:
        rule_action = (rule.action or "").strip().lower()
        if rule_action == req_action:
            continue  # same action isn't a conflict - it's the "same policy" case handled elsewhere
        if (
            covers(rule.fromzone, {req_source_zone})
            and covers_addresses(rule.source, req_source_addr)
            and covers(rule.tozone, {req_dest_zone})
            and covers_addresses(rule.destination, req_dest_addr)
            and covers(rule.service, req_service)
            and covers(rule.application, req_application)
        ):
            return rule
    return None


# --- Building the new-rule name -------------------------------------------

def make_rule_name(req: dict, dest_zone: str, taken_names: set) -> str:
    """Generates a rule name from Tag + Destination Zone + Action, since
    the Excel sheet doesn't include a dedicated rule-name column. Adjust
    this if you'd rather name rules differently - it's just string
    building, nothing tricky.

    dest_zone is the AUTO-RESOLVED zone from STEP 0, not an Excel column."""
    tag = str(req.get("Tag") or "rule").strip().replace(" ", "-")
    dest_zone = str(dest_zone or "any").strip().replace(" ", "-")
    action = str(req.get("Action") or "action").strip().replace(" ", "-")
    base_name = f"{tag}-{dest_zone}-{action}"

    name = base_name
    counter = 2
    while name in taken_names:
        name = f"{base_name}-{counter}"
        counter += 1
    return name


# --- Processing one request row -------------------------------------------

def normalize_application_list(raw_values: list):
    """PAN-OS's 'application-default' keyword is only valid in the
    SERVICE field (it means 'use whatever port is standard for the
    selected application') - it's not a valid value for the Application
    field itself, which is what caused the 'application-default is not
    an allowed keyword' error. If you don't know/care about the specific
    application, the right wildcard for the Application field is 'any' -
    so that's what this substitutes automatically. Returns
    (normalized_list, note_or_None)."""
    normalized = []
    substituted = False
    for value in raw_values:
        if value.strip().lower() in ("application-default", "app-default"):
            normalized.append("any")
            substituted = True
        else:
            normalized.append(value)
    note = None
    if substituted:
        note = "'application-default' isn't valid in the Application field (only in Service) - used 'any' instead"
    return normalized, note


def process_request(req: dict, existing_rules: list, taken_names: set, rulebase, fw, existing_services_by_name: dict, taken_service_names: set, known_tag_names: set, taken_tag_names: set, known_address_names: set, address_object_values: dict, virtual_routers_to_check: list, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict, apply_changes: bool) -> dict:
    """Runs one Request-sheet row through the full pipeline:
        resolve zones -> validate objects -> check existing rules ->
        check duplicate/shadowing -> show proposed change -> (apply)
    Returns a result dict for the Implementation sheet."""
    result = dict(req)  # start with the original columns, we'll add more
    result["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Normalized ONCE, right here, so every downstream step (zone lookup,
    # validation, matching, shadow check, and the rule itself) works off
    # the same canonical form - this is the fix for the duplicate-rule bug.
    req_source_list = normalize_address_list(split_values(req.get("Source")))
    # Also self-consolidate the Source list in case one cell lists several
    # values where one already covers another (e.g. "100.100.100.0/24,
    # 100.100.100.50/32" in the same cell) - same containment logic used
    # when merging into an existing rule, applied here so a brand-new rule
    # never starts out with redundant entries either.
    req_source_list, _ = merge_source_addresses([], req_source_list)
    req_dest_list = normalize_address_list(split_values(req.get("Destination")))
    raw_service_values = build_raw_service_values(req.get("Service"), req.get("Destination Port"))
    req_application_list, application_note = normalize_application_list(split_values(req.get("Application")) or ["any"])

    # --- STEP 0: Resolve zones from routing ---
    print("  [1/5] Resolving zones from routing...")
    source_zone, source_zone_problems = resolve_zone_for_list(
        fw, req_source_list, virtual_routers_to_check, address_object_values, interface_zone_cache, ip_zone_cache, route_cache
    )
    dest_zone, dest_zone_problems = resolve_zone_for_list(
        fw, req_dest_list, virtual_routers_to_check, address_object_values, interface_zone_cache, ip_zone_cache, route_cache
    )
    all_zone_problems = [f"Source: {p}" for p in source_zone_problems] + [f"Destination: {p}" for p in dest_zone_problems]
    if all_zone_problems:
        print(f"        Source zone: {source_zone or 'UNRESOLVED'}, Destination zone: {dest_zone or 'UNRESOLVED'}")
    else:
        print(f"        Source zone: {source_zone}, Destination zone: {dest_zone}")

    # If EVERY zone problem is specifically "no route" (either no route at
    # all, or ONLY the default route matched - see resolve_zone_for_value
    # and the DEFAULT-ROUTE EXCLUSION note in the module docstring), give
    # this its own clear outcome rather than lumping it in with generic
    # validation errors - this is a routing-visibility issue on the
    # firewall, not a mistake in the Excel data, so it deserves a message
    # that says so plainly. Critically: a default-route-only match is
    # treated exactly like no route at all, so a policy is NEVER created
    # off the strength of a default route alone.
    if all_zone_problems and all(("no route found" in p) or ("DEFAULT route" in p) for p in all_zone_problems):
        result["Rule Name"] = ""
        result["Outcome"] = "Could not implement - no specific route found"
        result["Details"] = (
            "Could not be implemented because no SPECIFIC route exists on any checked virtual router "
            "(a match against the default route alone does not count): "
            + "; ".join(all_zone_problems)
        )
        print(f"        FAILED: {result['Details']}")
        return result

    # --- STEP 1: Validate objects ---
    print("  [2/5] Validating objects...")
    problems = all_zone_problems + validate_row(req, raw_service_values, known_address_names, existing_services_by_name)
    if problems:
        result["Rule Name"] = ""
        result["Outcome"] = "Validation error"
        result["Details"] = "; ".join(problems)
        print(f"        FAILED: {result['Details']}")
        return result

    # Turn the raw Service cell (which might be a bare port like "443")
    # into real service names, creating a Service object on the firewall
    # for any bare port we haven't seen before.
    resolved_service_names, service_notes = resolve_service_names(
        raw_service_values, existing_services_by_name, taken_service_names, fw, apply_changes
    )

    req_source_set = set(req_source_list)
    req_dest_set = set(req_dest_list)

    # --- STEP 2: Check existing rules ---
    print("  [3/5] Checking existing rules...")
    matched_rule = find_matching_rule(existing_rules, req, resolved_service_names, req_application_list, source_zone, dest_zone, req_dest_set)

    # --- STEP 3: Check duplicate / shadowing ---
    print("  [4/5] Checking for duplicates/shadowing...")
    merged_sources = None  # set below if this row turns out to be a merge
    if matched_rule is not None:
        # Same destination/service/application/action already exists - add
        # the new source address(es) into that rule instead of duplicating.
        # merge_source_addresses() understands subnet containment (e.g. a
        # host address already covered by a broader network already in
        # the rule doesn't get added as a redundant extra entry) - see its
        # docstring for the exact bug this fixes.
        current_sources = normalize_address_list(matched_rule.source or [])
        merged_sources, source_changes = merge_source_addresses(current_sources, req_source_list)

        result["Rule Name"] = matched_rule.name
        if not source_changes:
            result["Outcome"] = "Duplicate - already exists"
            result["Details"] = f"Rule '{matched_rule.name}' already covers this exact request - nothing to do."
        else:
            result["Outcome"] = "Merged into existing rule"
            details = f"Updated source on rule '{matched_rule.name}': " + "; ".join(source_changes) + "."
            if service_notes:
                details += " Also created " + ", ".join(service_notes) + "."
            if application_note:
                details += " " + application_note + "."
            result["Details"] = details
    else:
        shadow_rule = check_shadowing(existing_rules, req, resolved_service_names, req_application_list, source_zone, dest_zone, req_source_set, req_dest_set)
        if shadow_rule is not None:
            result["Rule Name"] = ""
            result["Outcome"] = "Shadow conflict - not created"
            result["Details"] = (
                f"Existing rule '{shadow_rule.name}' (action={shadow_rule.action}) already matches this traffic "
                f"and sits earlier in the rulebase - a new rule below it would never be reached. "
                f"Not creating anything - review rule order manually."
            )
        else:
            result["Rule Name"] = None  # placeholder, filled in below once we know apply_changes' outcome

    # --- STEP 4: Show proposed change ---
    if result.get("Rule Name") is None:
        # No match, no shadow conflict - this is the "create a new rule" case.
        new_name = make_rule_name(req, dest_zone, taken_names)
        taken_names.add(new_name)

        # Auto-create any Tag that doesn't exist yet on the firewall -
        # PAN-OS rejects a rule create/commit if its Tag values don't
        # reference real Tag objects. Blank Tag cell = no tags, fine.
        resolved_tag_names, tag_notes = resolve_tags(
            split_values(req.get("Tag")), known_tag_names, taken_tag_names, fw, apply_changes
        )

        new_rule = SecurityRule(
            name=new_name,
            fromzone=[source_zone],
            tozone=[dest_zone],
            source=req_source_list,
            destination=req_dest_list,
            service=resolved_service_names,
            application=req_application_list,
            action=str(req.get("Action") or "").strip(),
            tag=resolved_tag_names,
        )

        result["Rule Name"] = new_name
        result["Outcome"] = "Created new rule"
        details = f"No existing rule matched, created '{new_name}' (Source Zone: {source_zone}, Destination Zone: {dest_zone})."
        if service_notes:
            details += " Also created " + ", ".join(service_notes) + "."
        if tag_notes:
            details += " Also created " + ", ".join(tag_notes) + "."
        if application_note:
            details += " " + application_note + "."
        result["Details"] = details

        # --- STEP 5: Apply (or not) ---
        # existing_rules.append() happens UNCONDITIONALLY (not just when
        # apply_changes is True) - this is what makes a DRY RUN correctly
        # simulate the whole batch: if row 2 proposes a new rule and row 6
        # would be identical to it, row 6 needs to see row 2's proposed
        # rule in this same in-memory list to report "Duplicate" instead
        # of independently proposing a second new rule. Only the actual
        # device write (rulebase.add + create) is gated by apply_changes.
        if apply_changes:
            rulebase.add(new_rule)
            new_rule.create()
        existing_rules.append(new_rule)
    else:
        # Merge / duplicate / shadow cases already decided their Outcome
        # and Details above. The in-memory source-list update happens
        # UNCONDITIONALLY for the same batch-simulation reason as above -
        # only the actual device write (matched_rule.update("source")) is
        # gated by apply_changes.
        if result["Outcome"] == "Merged into existing rule":
            matched_rule.source = merged_sources
            if apply_changes:
                matched_rule.update("source")

    print(f"  [5/5] Proposed change: {result['Outcome']} - {result['Details']}")
    return result


# --- Writing the Implementation sheet -------------------------------------

def write_results(excel_path: Path, sheet_name: str, results: list):
    wb = openpyxl.load_workbook(excel_path)

    if sheet_name in wb.sheetnames:
        del wb[sheet_name]  # simplest option: rewrite the sheet fresh each run
    ws = wb.create_sheet(sheet_name)

    columns = REQUEST_COLUMNS + ["Rule Name", "Outcome", "Details", "Timestamp"]
    ws.append(columns)
    for result in results:
        ws.append([result.get(col, "") for col in columns])

    wb.save(excel_path)


# --- Main ------------------------------------------------------------------

def main():
    # Every setting below can come from paloalto_config.json, so this
    # script runs fine with ZERO command-line arguments - required for
    # double-clicking it, running it via IDLE's "Run Module", or running
    # it as a packaged .exe, none of which pass command-line flags.
    #
    # If you DO run it from a terminal, these flags are still available
    # and will override whatever the config file says for that one run.
    parser = argparse.ArgumentParser(description="Validate and push Palo Alto security policies from an Excel sheet.")
    parser.add_argument("--excel", default=None, help="Path to the Excel file (default: excel_path from paloalto_config.json)")
    parser.add_argument("--request-sheet", default=None, help="Sheet name with the requested policies (default: request_sheet from config)")
    parser.add_argument("--implementation-sheet", default=None, help="Sheet name to write results to (default: implementation_sheet from config)")
    parser.add_argument("--apply", action="store_true", default=None, help="Actually create/update rules on the firewall (default: apply from config)")
    parser.add_argument("--commit", action="store_true", default=None, help="Commit the candidate config after applying (default: commit from config)")
    args = parser.parse_args()

    print("Connecting to firewall...")
    config = load_config()

    # CLI flag wins if given; otherwise fall back to the config file value.
    excel_path = Path(args.excel if args.excel is not None else config["excel_path"])
    request_sheet = args.request_sheet if args.request_sheet is not None else config["request_sheet"]
    implementation_sheet = args.implementation_sheet if args.implementation_sheet is not None else config["implementation_sheet"]
    apply_changes = args.apply if args.apply is not None else config["apply"]
    do_commit = args.commit if args.commit is not None else config["commit"]

    # excel_path is relative to the script's (or .exe's) own folder, not
    # wherever the command happened to be run from - see get_base_dir()
    # for why this uses that instead of Path(__file__).parent directly.
    if not excel_path.is_absolute():
        excel_path = get_base_dir() / excel_path

    print(f"Excel file: {excel_path}")
    if not excel_path.exists():
        print(f"ERROR: Excel file not found at {excel_path}")
        print("Check 'excel_path' in paloalto_config.json, or pass --excel if running from a terminal.")
        sys.exit(1)

    if do_commit and not apply_changes:
        print("NOTE: 'commit' is on but 'apply' is off - nothing would be changed, so there's nothing to commit. Ignoring commit for this run.")
        do_commit = False

    fw, rulebase, existing_rules, existing_services_by_name, known_tag_names, zone_names, known_address_names, address_object_values, virtual_routers_to_check = connect_to_firewall(config)
    taken_names = {rule.name for rule in existing_rules}
    taken_service_names = set()  # tracks service objects created/reused during THIS run
    taken_tag_names = set()  # tracks tag objects created/reused during THIS run
    interface_zone_cache = {}  # interface name -> zone, so STEP 0 never re-queries the same interface
    ip_zone_cache = {}  # ip -> (zone, error), so STEP 0 never re-runs a FIB lookup for the same IP
    route_cache = {}  # virtual router name -> list of routes, so the default-route check never re-fetches the same VR's table
    print(f"Found {len(existing_rules)} existing security rule(s) on the firewall.")
    print(f"Found {len(existing_services_by_name)} existing service object(s), {len(known_tag_names)} tag(s), {len(zone_names)} zone(s), {len(known_address_names)} address object(s)/group(s) on the firewall.")
    print(f"Checking virtual router(s) for zone-from-routing lookups: {', '.join(virtual_routers_to_check)}")

    print(f"Reading requests from '{request_sheet}' sheet...")
    requests = read_requests(excel_path, request_sheet)
    print(f"Found {len(requests)} request row(s).")

    print(f"\nMODE: {'APPLY' if apply_changes else 'DRY RUN'}" + (" + COMMIT" if do_commit else ""))
    if not apply_changes:
        print("No changes will be made on the firewall. Set \"apply\": true in paloalto_config.json to actually push changes.\n")
    else:
        print()

    results = []
    for i, req in enumerate(requests, start=1):
        print(f"Row {i}:")
        result = process_request(
            req, existing_rules, taken_names, rulebase, fw,
            existing_services_by_name, taken_service_names,
            known_tag_names, taken_tag_names,
            known_address_names, address_object_values, virtual_routers_to_check,
            interface_zone_cache, ip_zone_cache, route_cache,
            apply_changes=apply_changes,
        )
        results.append(result)

    print(f"\nWriting results to '{implementation_sheet}' sheet in {excel_path}...")
    write_results(excel_path, implementation_sheet, results)

    if apply_changes and do_commit:
        print("Committing candidate config to the firewall (this can take a minute)...")
        commit_result = fw.commit(sync=True)
        print(f"Commit result: {commit_result}")
    elif apply_changes:
        print("Changes were applied to the CANDIDATE config but NOT committed. Set \"commit\": true in paloalto_config.json (or --commit) to make them live, or commit manually.")

    merged = sum(1 for r in results if r["Outcome"] == "Merged into existing rule")
    created = sum(1 for r in results if r["Outcome"] == "Created new rule")
    duplicates = sum(1 for r in results if r["Outcome"] == "Duplicate - already exists")
    shadowed = sum(1 for r in results if r["Outcome"] == "Shadow conflict - not created")
    no_route = sum(1 for r in results if r["Outcome"] == "Could not implement - no specific route found")
    invalid = sum(1 for r in results if r["Outcome"] == "Validation error")
    print(f"\nSummary: {merged} merged, {created} created, {duplicates} duplicate, {shadowed} shadow conflict(s), {no_route} no-route, {invalid} validation error(s).")


if __name__ == "__main__":
    main()
    # Keeps the console window open when double-clicked (or run as a .exe)
    # so you can actually read the output before it closes. Harmless when
    # run from a terminal or IDLE - just press Enter to close.
    input("\nDone. Press Enter to close this window...")
