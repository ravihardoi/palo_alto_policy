import os
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
from panos.errors import PanNoSuchNode, PanObjectMissing


def get_base_dir() -> Path:
    """The folder this script (or the packaged .exe) actually lives in -
    used to find paloalto_config.json and, by default, requests.xlsx.
    Under PyInstaller, __file__ points at a temp extraction folder, so
    sys.executable's folder is used instead when sys.frozen is set."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent


CONFIG_FILE = get_base_dir() / "paloalto_config.json"

# "Source Group", "Destination Group" and "Justification" are optional columns:
# requests.xlsx files without them keep working.
REQUEST_COLUMNS = [
    "Tag", "Source", "Destination", "Destination Port", "Application", "Service", "Action",
    "Source Group", "Destination Group", "Justification",
]

VALID_ACTIONS = {"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}

# Loose IP / CIDR / range matcher - tells "raw address" apart from
# "object name". A sanity check, not a full validator.
IP_LIKE_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){0,3}(/\d{1,2})?(-\d{1,3}(\.\d{1,3}){0,3})?$")

# The three "traffic" fields the duplicate/merge logic compares.
# Destination Port lives inside "service" (e.g. svc-tcp-8443).
MERGEABLE_FIELDS = ("source", "destination", "service")

# Which single field may differ when adding a request to an existing rule.
# Policy: only a new Source is consolidated. A different destination,
# application or service gets its own rule. Override with "consolidate_fields"
# in paloalto_config.json if the policy changes.
DEFAULT_CONSOLIDATE_FIELDS = ["source"]

# PAN-OS object names: start alphanumeric, 63 characters at most.
OBJECT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,62}$")


def normalize_address(value: str) -> str:
    """Normalizes an IP/CIDR to its canonical network form, so e.g.
    '50.50.50.50/24' and '50.50.50.0/24' compare equal. "any", ranges and
    object/group names are returned unchanged."""
    text = value.strip()
    if text.lower() == "any":
        return "any"
    if "/" in text and "-" not in text:
        try:
            return str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            return text  # not a valid CIDR - validate_row() will flag it
    return text


def normalize_address_list(values: list) -> list:
    return [normalize_address(v) for v in values]


def to_networks(value: str):
    """Literal IP, CIDR or full range -> list of networks. None if it isn't one."""
    text = str(value).strip()
    try:
        if "-" in text:
            first, last = text.split("-", 1)
            return list(ipaddress.summarize_address_range(
                ipaddress.ip_address(first.strip()), ipaddress.ip_address(last.strip())))
        return [ipaddress.ip_network(text, strict=False)]
    except (ValueError, TypeError):
        return None


def safe_object_name(text: str) -> str:
    """Turns free text into a valid PAN-OS object name."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(text).strip()).strip("_.-")
    return cleaned or "object"


# --- Address objects and groups --------------------------------------------

class AddressBook:
    """The firewall's address objects and groups, plus the changes planned so
    far in this run. Understands that '10.1.1.10', '10.1.1.10/32', an object
    holding that IP and a group containing that object are the same address.

    Anything that can't be turned into an IP (FQDN object, dynamic group, an
    object in another scope) is compared by name only, so it is never assumed
    to cover another address."""

    def __init__(self, fw, address_objects: list, address_groups: list, outside_references):
        self.fw = fw
        self.objects = {a.name: a for a in address_objects}
        self.groups = {g.name: g for g in address_groups}
        # Names used by NAT, PBF, decryption rules etc. None = couldn't be read,
        # in which case no existing group is treated as safe to change.
        self.outside_references = outside_references

    def object_values(self) -> dict:
        return {name: obj.value for name, obj in self.objects.items()}

    def expand(self, value: str, _seen=None) -> set:
        """One rule entry -> set of networks, plus names for what can't resolve."""
        text = str(value).strip()
        if text.lower() == "any":
            return {"any"}
        seen = _seen if _seen is not None else set()
        if text in self.groups:
            members = self.groups[text].static_value
            if not members or text in seen:
                return {text}
            seen.add(text)
            tokens = set()
            for member in members:
                tokens |= self.expand(member, seen)
            return tokens
        if text in self.objects:
            obj = self.objects[text]
            if (obj.type or "ip-netmask") in ("ip-netmask", "ip-range"):
                networks = to_networks(obj.value) if obj.value else None
                if networks:
                    return set(networks)
            return {text}
        networks = to_networks(text)
        return set(networks) if networks else {text}

    def expand_all(self, values) -> set:
        tokens = set()
        for value in values or []:
            tokens |= self.expand(value)
        return tokens

    def canonical(self, values) -> set:
        """Comparable form: adjacent or nested networks collapse together."""
        tokens = self.expand_all(values)
        canonical = {t for t in tokens if isinstance(t, str)}
        for version in (4, 6):
            networks = [t for t in tokens if not isinstance(t, str) and t.version == version]
            canonical |= set(ipaddress.collapse_addresses(networks))
        return canonical

    def same(self, values_a, values_b) -> bool:
        return self.canonical(values_a) == self.canonical(values_b)

    def covers(self, rule_values, requested_values) -> bool:
        """True if the rule entries include every requested address."""
        rule_tokens = self.expand_all(rule_values)
        if not rule_tokens or "any" in rule_tokens:
            return True
        for token in self.expand_all(requested_values):
            if isinstance(token, str):
                if token not in rule_tokens:
                    return False
            elif not any(
                not isinstance(r, str) and r.version == token.version and token.subnet_of(r)
                for r in rule_tokens
            ):
                return False
        return True

    def flatten_for_zone_lookup(self, values, _seen=None) -> list:
        """Replaces static groups with their members for routing lookups."""
        seen = _seen if _seen is not None else set()
        flat = []
        for value in values:
            members = self.groups[value].static_value if value in self.groups else None
            if members and value not in seen:
                seen.add(value)
                flat.extend(self.flatten_for_zone_lookup(members, seen))
            else:
                flat.append(value)
        return flat

    def unique_name(self, wanted: str) -> str:
        base = wanted[:63]
        name = base
        counter = 2
        while name in self.objects or name in self.groups:
            suffix = f"-{counter}"
            name = base[:63 - len(suffix)] + suffix
            counter += 1
        return name

    def find_object_for(self, value: str):
        """An existing object holding exactly this address, so it gets reused."""
        networks = to_networks(value)
        if not networks:
            return None
        wanted = set(ipaddress.collapse_addresses(networks))
        for name, obj in self.objects.items():
            if (obj.type or "ip-netmask") not in ("ip-netmask", "ip-range") or not obj.value:
                continue
            existing = to_networks(obj.value)
            if existing and set(ipaddress.collapse_addresses(existing)) == wanted:
                return name
        return None

    def ensure_object(self, value: str, role: str, explicit_name, actions: list, notes: list) -> str:
        """Returns an object name for this value, planning a new object if needed.
        Names that aren't literal addresses are returned unchanged."""
        networks = to_networks(value)
        if value in self.objects or value in self.groups or not networks:
            return value
        if explicit_name and explicit_name in self.objects:
            return explicit_name
        reuse = self.find_object_for(value)
        if reuse:
            if explicit_name and explicit_name != reuse:
                notes.append(f"reused existing address object '{reuse}' for {value} instead of creating '{explicit_name}'")
            return reuse

        is_range = "-" in value
        is_host = not is_range and networks[0].prefixlen == networks[0].max_prefixlen
        label = str(networks[0].network_address) if is_host else value
        name = explicit_name or self.unique_name(f"{role}_{safe_object_name(label)}")
        object_value = value if is_range else str(networks[0])
        obj = AddressObject(name=name, value=object_value, type="ip-range" if is_range else "ip-netmask")
        self.objects[name] = obj

        def push(new_object=obj):
            self.fw.add(new_object)
            new_object.create()
        actions.append(push)
        notes.append(f"created address object '{name}' ({object_value})")
        return name

    def create_group(self, name: str, members: list, actions: list, notes: list):
        group = AddressGroup(name=name, static_value=list(members))
        self.groups[name] = group

        def push(new_group=group):
            self.fw.add(new_group)
            new_group.create()
        actions.append(push)
        notes.append(f"created address group '{name}' with members {', '.join(members)}")

    def is_exclusive_to(self, group_name: str, rule, field: str, existing_rules: list) -> bool:
        """True only if changing this group can't affect any other policy.
        A group shared with another rule must never be changed here, because
        adding a member would silently widen that other rule too."""
        if self.outside_references is None or group_name in self.outside_references:
            return False
        for other_name, other_group in self.groups.items():
            if other_name != group_name and group_name in (other_group.static_value or []):
                return False
        for other_rule in existing_rules:
            for rule_field in ("source", "destination"):
                if other_rule is rule and rule_field == field:
                    continue
                if group_name in (getattr(other_rule, rule_field) or []):
                    return False
        return True


# --- Config / connection -------------------------------------------------

def load_config() -> dict:
    """Loads run-mode settings from paloalto_config.json (optional).
    Connection details are NOT read from here any more - see
    load_awx_connection()."""
    config = {}
    if CONFIG_FILE.exists():
        config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))

    for leftover in ("hostname", "api_key", "username", "password"):
        if config.get(leftover):
            print(f"WARNING: '{leftover}' in {CONFIG_FILE.name} is ignored - the firewall and credentials "
                  f"now come from AWX (PANOS_* environment variables). Please remove it from the file.")

    config.setdefault("excel_path", "requests.xlsx")
    config.setdefault("request_sheet", "Request")
    config.setdefault("implementation_sheet", "Implementation")
    config.setdefault("apply", False)
    config.setdefault("commit", False)
    config.setdefault("virtual_router", None)  # None = check every virtual router
    config.setdefault("consolidate_fields", list(DEFAULT_CONSOLIDATE_FIELDS))

    unknown_fields = [f for f in config["consolidate_fields"] if f not in MERGEABLE_FIELDS]
    if unknown_fields:
        print(f"ERROR: consolidate_fields in {CONFIG_FILE.name} has unknown value(s) {unknown_fields}. "
              f"Allowed: {', '.join(MERGEABLE_FIELDS)}.")
        sys.exit(1)
    return config


def load_awx_connection() -> dict:
    """Reads the firewall address (from the AWX inventory host) and the
    credential (from the AWX custom credential type) out of environment
    variables. Nothing secret is ever stored in this script or its
    config file."""
    hostname = os.environ.get("PANOS_HOSTNAME", "").strip()
    api_key = os.environ.get("PANOS_API_KEY", "").strip()
    username = os.environ.get("PANOS_USERNAME", "").strip()
    password = os.environ.get("PANOS_PASSWORD", "")  # not stripped - spaces can be part of a password

    if not hostname:
        print("ERROR: PANOS_HOSTNAME is not set. In AWX this comes from the inventory host "
              "(see awx_run_policy_manager.yml). For a local test, set it yourself.")
        sys.exit(1)
    if not api_key and not (username and password):
        print("ERROR: no credential found. Attach the 'Palo Alto PAN-OS API' credential to the AWX job "
              "template, so it injects PANOS_API_KEY (or PANOS_USERNAME + PANOS_PASSWORD).")
        sys.exit(1)

    return {"hostname": hostname, "api_key": api_key, "username": username, "password": password}


def connect_to_firewall(connection: dict, config: dict):
    """Connects to the firewall and pulls back everything the validation,
    zone-resolution, and matching steps need. Returns (firewall_object,
    rulebase_object, list_of_existing_rules, dict_of_existing_services_by_name,
    set_of_known_tag_names, set_of_zone_names, address_book,
    list_of_virtual_router_names_to_check)."""
    if connection["api_key"]:
        fw = Firewall(connection["hostname"], api_key=connection["api_key"])
    else:
        fw = Firewall(connection["hostname"], connection["username"], connection["password"])

    rulebase = fw.add(Rulebase())
    existing_rules = SecurityRule.refreshall(rulebase)

    existing_services = ServiceObject.refreshall(fw)
    existing_services_by_name = {s.name: s for s in existing_services}

    known_tag_names = {t.name for t in Tag.refreshall(fw)}

    zone_names = {z.name for z in Zone.refreshall(fw)}

    address_book = AddressBook(
        fw,
        AddressObject.refreshall(fw),
        AddressGroup.refreshall(fw),
        read_outside_references(fw),
    )

    all_virtual_router_names = [vr.name for vr in VirtualRouter.refreshall(fw)]
    if not all_virtual_router_names:
        print("ERROR: no virtual routers found on this firewall - can't do routing-based zone lookups.")
        sys.exit(1)

    forced_virtual_router = config.get("virtual_router")
    if forced_virtual_router:
        if forced_virtual_router not in all_virtual_router_names:
            print(f"ERROR: virtual_router '{forced_virtual_router}' not found on the firewall. Available: {all_virtual_router_names}")
            sys.exit(1)
        virtual_routers_to_check = [forced_virtual_router]
    else:
        virtual_routers_to_check = all_virtual_router_names

    return fw, rulebase, existing_rules, existing_services_by_name, known_tag_names, zone_names, address_book, virtual_routers_to_check


def read_outside_references(fw):
    """Every name mentioned by non-security rulebases (NAT, PBF, decryption...),
    so a group those rules use is never changed. Returns None if unreadable."""
    try:
        root = fw.xapi.get(fw.xpath_vsys() + "/rulebase")
    except (PanObjectMissing, PanNoSuchNode):
        return set()
    except Exception as e:
        print(f"WARNING: couldn't read the other rulebases ({e}) - existing address groups won't be changed in this run.")
        return None
    references = set()
    result = root.find("./result")
    if result is None:
        return references
    for rulebase_elem in result.iter("rulebase"):
        for section in rulebase_elem:
            if section.tag == "security":
                continue
            for elem in section.iter():
                if elem.text and elem.text.strip():
                    references.add(elem.text.strip())
    return references


# --- STEP 0: Resolving zones from the routing table -----------------------

def get_ip_for_lookup(value: str, address_object_values: dict):
    """Turns one Source/Destination value into a single IP for a FIB
    lookup. Returns (ip_or_None, error_or_None); ("any", None) for 'any'."""
    text = value.strip()
    if text.lower() == "any":
        return ("any", None)

    if IP_LIKE_PATTERN.match(text):
        base = text.split("/")[0].split("-")[0]
        return (base, None)

    if text in address_object_values:
        object_value = address_object_values.get(text)
        if not object_value:
            return (None, f"Address object '{text}' has no value set")
        base = str(object_value).split("/")[0].split("-")[0]
        return (base, None)

    return (None, f"'{text}' is an Address group or unknown object - can't auto-resolve its zone, specify manually")


def fib_lookup_interface(fw, ip: str, virtual_router: str):
    """Which interface would the firewall route this IP through? None if no route."""
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
    """Which zone is this interface in? Cached per run."""
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
    """All routes in one VR's table ("show routing route"), cached per run.
    Used only to tell a specific-route match from a default-route match."""
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
            continue
    route_cache[virtual_router] = routes
    return routes


def most_specific_route_prefixlen(routes: list, ip: str):
    """Prefix length of the most specific route containing this IP, or
    None if nothing covers it. 0 means default-route only."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    matching = [net for net in routes if address in net]
    if not matching:
        return None
    return max(net.prefixlen for net in matching)


def resolve_zone_for_value(fw, value: str, virtual_routers_to_check: list, address_object_values: dict, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict):
    """Resolves ONE Source/Destination value to a single zone, checking
    every VR in virtual_routers_to_check. Returns (zone_or_None, error_or_None)."""
    ip, error = get_ip_for_lookup(value, address_object_values)
    if error:
        return (None, error)
    if ip == "any":
        return ("any", None)

    if ip in ip_zone_cache:
        return ip_zone_cache[ip]

    zone_by_vr = {}
    default_route_only_vrs = []
    for vr in virtual_routers_to_check:
        try:
            routes = get_virtual_router_routes(fw, vr, route_cache)
        except RuntimeError:
            routes = None  # couldn't read the table - fall back to trusting the FIB lookup
        if routes is not None:
            prefixlen = most_specific_route_prefixlen(routes, ip)
            if prefixlen == 0:
                default_route_only_vrs.append(vr)
                continue
        try:
            interface_name = fib_lookup_interface(fw, ip, vr)
        except RuntimeError:
            continue
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


def resolve_zone_for_list(fw, values: list, virtual_routers_to_check: list, address_book, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict):
    """Resolves a whole Source or Destination cell to one zone, looking inside
    static address groups. Returns (zone_or_None, list_of_problem_strings)."""
    zones_found = set()
    problems = []
    address_object_values = address_book.object_values()

    for value in address_book.flatten_for_zone_lookup(values):
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
# Accepted formats in the Service column:
#   any / application-default -> used as-is
#   443 or tcp/443            -> object "svc-tcp-443" (auto-created)
#   udp/53                    -> object "svc-udp-53"  (auto-created)
#   service-https             -> assumed to be an existing object name

PORT_PATTERN = re.compile(r"^(tcp|udp)?[/\s]?(\d+)$", re.IGNORECASE)


def parse_service_entry(raw_value: str):
    """Returns ("keyword", kw) / ("port", protocol, port) / ("name", raw_value)."""
    text = raw_value.strip()
    if text.lower() in ("any", "application-default"):
        return ("keyword", text.lower())

    match = PORT_PATTERN.match(text)
    if match:
        protocol = (match.group(1) or "tcp").lower()
        port = match.group(2)
        return ("port", protocol, port)

    return ("name", text)


def resolve_service_names(raw_service_values: list, existing_services_by_name: dict):
    """Turns raw Service values into names valid on a security rule. Nothing is
    created here, because the row may turn out to be a duplicate. Returns
    (resolved_names, list_of_(name, protocol, port)_to_create)."""
    resolved_names = []
    to_create = []

    for raw_value in raw_service_values:
        kind, *rest = parse_service_entry(raw_value)

        if kind in ("keyword", "name"):
            resolved_names.append(rest[0])
            continue

        protocol, port = rest
        object_name = f"svc-{protocol}-{port}"
        resolved_names.append(object_name)

        if object_name not in existing_services_by_name and object_name not in [t[0] for t in to_create]:
            to_create.append((object_name, protocol, port))

    return resolved_names, to_create


def plan_service_objects(to_create: list, existing_services_by_name: dict, fw, actions: list, notes: list):
    for object_name, protocol, port in to_create:
        new_service = ServiceObject(name=object_name, protocol=protocol, destination_port=port)
        existing_services_by_name[object_name] = new_service

        def push(service=new_service):
            fw.add(service)
            service.create()
        actions.append(push)
        notes.append(f"created service object '{object_name}' ({protocol}/{port})")


def apply_application_id_policy(req: dict, application_list: list, raw_service_values: list):
    """Prefer Application-ID over port-based policy. Returns (service_values,
    notes, problems):
      - named application + blank or 'any' service -> application-default
      - 'any' service is kept only with text in the Justification column
      - port-only rule (Application 'any') is allowed but flagged
      - Application 'any' + Service 'any' is refused without a Justification"""
    justification = str(req.get("Justification") or "").strip()
    named_application = set(application_list) != {"any"}
    lowered = [str(v).strip().lower() for v in raw_service_values]
    has_any = "any" in lowered
    has_default = "application-default" in lowered
    has_ports = any(parse_service_entry(v)[0] == "port" for v in raw_service_values)

    if has_default and len(raw_service_values) > 1:
        return raw_service_values, [], ["Service can't mix application-default with other services or ports"]

    if named_application:
        if not raw_service_values:
            return ["application-default"], ["Service was blank, so used application-default (App-ID preferred)"], []
        if has_any:
            if justification:
                return raw_service_values, [f"service 'any' kept because of the Justification: {justification}"], []
            return ["application-default"], ["Service 'any' replaced with application-default; add a Justification to keep 'any'"], []
        return raw_service_values, [], []

    if has_default:
        return raw_service_values, [], ["application-default needs a named Application, not 'any'"]
    if has_any or not raw_service_values:
        if has_any and justification:
            return raw_service_values, [f"Application and Service 'any' kept because of the Justification: {justification}"], []
        return raw_service_values, [], ["Application and Service can't both be 'any' or blank - name the application, or add a Justification"]
    if has_ports:
        return raw_service_values, ["port-based rule: Application is 'any', so consider naming the App-ID with application-default"], []
    return raw_service_values, [], []


# --- Resolving Tag cell values into valid PAN-OS tag references ------------

def plan_tags(raw_tag_values: list, known_tag_names: set, fw, actions: list, notes: list):
    """Plans any Tag object that doesn't exist yet. Returns the tag names."""
    for tag_name in raw_tag_values:
        if tag_name in known_tag_names:
            continue
        known_tag_names.add(tag_name)
        new_tag = Tag(name=tag_name)

        def push(tag=new_tag):
            fw.add(tag)
            tag.create()
        actions.append(push)
        notes.append(f"created tag '{tag_name}'")
    return raw_tag_values


def build_raw_service_values(service_cell, dest_port_cell) -> list:
    """Combines Service and Destination Port into raw service values.
    If Destination Port is set, it's authoritative and Service supplies
    the protocol by position (default tcp); extra Service entries are
    kept as-is. If Destination Port is empty, Service is used as before."""
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
    """'10.1.1.5, 10.1.1.6' -> ['10.1.1.5', '10.1.1.6']"""
    if cell_value is None:
        return []
    text = str(cell_value).strip()
    if not text:
        return []
    return [part.strip() for part in text.split(",") if part.strip()]


def parse_address_cell(cell_value):
    """'10.1.1.5, SRC_APP_02=10.1.1.6' -> (values, {value: object_name}).
    NAME=IP is optional and names the address object created for that IP."""
    values = []
    names = {}
    for part in split_values(cell_value):
        if "=" in part:
            name, value = part.split("=", 1)
            value = normalize_address(value)
            names[value] = name.strip()
            values.append(value)
        else:
            values.append(normalize_address(part))
    consolidated, _ = merge_addresses([], values)
    return consolidated, names


def read_requests(excel_path: Path, sheet_name: str) -> list:
    """Reads the request sheet into a list of dicts keyed by header."""
    wb = openpyxl.load_workbook(excel_path, data_only=True)
    if sheet_name not in wb.sheetnames:
        print(f"ERROR: sheet '{sheet_name}' not found in {excel_path}. Sheets present: {wb.sheetnames}")
        sys.exit(1)
    ws = wb[sheet_name]

    header_row = [cell.value for cell in ws[1]]
    rows = []
    for row_cells in ws.iter_rows(min_row=2, values_only=True):
        row_dict = dict(zip(header_row, row_cells))
        if all(v is None or str(v).strip() == "" for v in row_dict.values()):
            continue
        rows.append(row_dict)
    return rows


# --- STEP 1: Validating objects -------------------------------------------

def looks_like_address(value: str, address_book) -> bool:
    if value.lower() == "any":
        return True
    if value in address_book.objects or value in address_book.groups:
        return True
    return bool(IP_LIKE_PATTERN.match(value)) and to_networks(value) is not None


def name_problems(names: dict, address_book) -> list:
    """Checks the NAME=IP names given in a Source or Destination cell."""
    problems = []
    for value, name in names.items():
        if not OBJECT_NAME_PATTERN.match(name):
            problems.append(f"'{name}' isn't a valid object name (letters, digits, . _ - and spaces, 63 characters at most)")
        elif name in address_book.groups:
            problems.append(f"'{name}' is already an address group, so it can't also name {value}")
        elif name in address_book.objects and not address_book.same([name], [value]):
            problems.append(f"address object '{name}' already exists with a different value, so it can't hold {value}")
    return problems


def validate_row(req: dict, source_addrs: list, dest_addrs: list, raw_service_values: list, address_book, existing_services_by_name: dict) -> list:
    """Returns a list of problems with one request row (empty = OK)."""
    problems = []

    if not source_addrs:
        problems.append("Source is empty")
    if not dest_addrs:
        problems.append("Destination is empty")
    for addr in source_addrs + dest_addrs:
        if not looks_like_address(addr, address_book):
            problems.append(f"'{addr}' doesn't look like a valid IP/CIDR and isn't a known Address object or group")

    dest_ports = split_values(req.get("Destination Port"))
    for port in dest_ports:
        if not port.isdigit():
            problems.append(f"Destination Port '{port}' isn't a number")

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


# --- Coverage helpers -------------------------------------------------------

def covers(rule_field_values, req_values: set) -> bool:
    """True if the rule's field covers every requested value ('any'/empty
    covers everything). Exact string match - for zones/service/app."""
    rule_set = set(rule_field_values or [])
    if not rule_set or "any" in rule_set:
        return True
    return req_values.issubset(rule_set)


def _as_network_or_none(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


# --- Merging values into an existing rule -------------------------------------

def merge_addresses(current_values: list, new_values: list):
    """Merges new Source OR Destination address(es) into an existing
    rule's list, subnet-aware: a value already covered by a broader
    network isn't added; a new broader network replaces narrower entries
    it now covers. Returns (merged_list, change_descriptions) - empty
    descriptions means nothing changed."""
    merged = list(current_values)
    changes = []

    for new_value in new_values:
        if new_value in merged:
            continue

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
                    continue
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

    # A list of only "already covered" notes means nothing actually changed.
    if not any(c.startswith(("added", "removed")) for c in changes):
        return merged, []
    return merged, changes


def merge_service_names(current_services: list, new_services: list):
    """Merges new service name(s) into an existing rule's service list. Only
    used if "service" is listed in consolidate_fields. Returns (merged_list,
    change_descriptions)."""
    merged = list(current_services)
    changes = []
    for service in new_services:
        if service not in merged:
            merged.append(service)
            changes.append(f"added '{service}'")
    return merged, changes


def group_column_problem(address_book, group_name: str, values: list, rule, field: str, existing_rules: list):
    """Can the group named in the Excel column hold exactly these addresses?
    Returns a problem string, or None if it can."""
    if not group_name:
        return None
    if not OBJECT_NAME_PATTERN.match(group_name):
        return f"'{group_name}' isn't a valid group name (letters, digits, . _ - and spaces, 63 characters at most)"
    if group_name in address_book.objects:
        return f"'{group_name}' is already an address object, not a group"
    if group_name not in address_book.groups or address_book.same([group_name], values):
        return None
    if not address_book.covers(values, [group_name]):
        return f"address group '{group_name}' contains addresses that weren't requested - using it would allow more than asked"
    if not address_book.is_exclusive_to(group_name, rule, field, existing_rules):
        return f"address group '{group_name}' is used elsewhere - adding members would widen those policies too"
    return None


def prepare_address_entries(address_book, values: list, names: dict, group_name: str, role: str, base_name: str, actions: list, notes: list) -> list:
    """Works out what a rule's Source or Destination should contain. One plain
    address stays as it is; several become address objects in an address group."""
    if "any" in values:
        return ["any"]
    single = len(values) == 1
    if single and not group_name and not names.get(values[0]):
        return list(values)
    if single and values[0] in address_book.groups:
        return list(values)

    members = [address_book.ensure_object(v, role, names.get(v), actions, notes) for v in values]
    if single and not group_name:
        return members

    label = "SOURCES" if role == "SRC" else "DESTINATIONS"
    target = group_name or address_book.unique_name(f"GRP_{safe_object_name(base_name)[:40]}_{label}")
    if target in address_book.groups:
        group = address_book.groups[target]
        missing = [m for m in members if m not in (group.static_value or []) and not address_book.covers([target], [m])]
        if missing:
            group.static_value = list(group.static_value or []) + missing
            actions.append(lambda g=group: g.update("static_value"))
            notes.append(f"added {', '.join(missing)} to address group '{target}'")
    else:
        address_book.create_group(target, members, actions, notes)
    return [target]


def plan_address_merge(address_book, rule, field: str, new_values: list, names: dict, group_name: str, existing_rules: list, actions: list, notes: list):
    """Adds addresses to an existing rule's Source or Destination. Returns
    (change_descriptions, problem_or_None).

      - rule uses one group that nothing else uses -> add to that group
      - rule uses a group shared with other policies -> leave the group alone
        and add a separate object to this rule, so nothing else is widened
      - rule uses plain IPs or objects -> move them all into a new group"""
    role = "SRC" if field == "source" else "DST"
    current = list(getattr(rule, field) or [])
    to_add = [v for v in new_values if not address_book.covers(current, [v])]
    if not to_add:
        return [], None

    groups_in_rule = [entry for entry in current if entry in address_book.groups]

    if len(current) == 1 and groups_in_rule and address_book.groups[current[0]].static_value \
            and address_book.is_exclusive_to(current[0], rule, field, existing_rules):
        group = address_book.groups[current[0]]
        members = [address_book.ensure_object(v, role, names.get(v), actions, notes) for v in to_add]
        kept = [m for m in group.static_value if not address_book.covers(to_add, [m])]
        group.static_value = kept + [m for m in members if m not in kept]
        actions.append(lambda g=group: g.update("static_value"))
        changes = [f"added {', '.join(members)} to address group '{group.name}'"]
        if group_name and group_name != group.name:
            notes.append(f"Group column '{group_name}' not used - rule '{rule.name}' already has group '{group.name}'")
        return changes, None

    if groups_in_rule:
        members = [address_book.ensure_object(v, role, names.get(v), actions, notes) for v in to_add]
        updated = current + [m for m in members if m not in current]
        changes = [f"added {', '.join(members)} directly to the rule, because group '{', '.join(groups_in_rule)}' can't be changed safely"]
    else:
        kept = [entry for entry in current if not address_book.covers(to_add, [entry])]
        combined = kept + to_add
        problem = group_column_problem(address_book, group_name, combined, rule, field, existing_rules)
        if problem:
            return [], problem
        updated = prepare_address_entries(address_book, combined, names, group_name, role, rule.name, actions, notes)
        changes = [f"added {', '.join(to_add)}"]
        if updated != combined:
            changes.append(f"{field} is now {', '.join(updated)}")

    setattr(rule, field, updated)
    actions.append(lambda r=rule, f=field: r.update(f))
    return changes, None


# --- STEP 2/3: Matching an existing rule (duplicate or merge) -----------------

def rule_is_plain(rule) -> bool:
    """True if a rule's zones, addresses, app and service tell the whole story.
    A disabled or negated rule, or one limited by user, category, HIP or
    schedule, doesn't really allow this traffic, so it's left alone."""
    if rule.disabled or rule.negate_source or rule.negate_destination or rule.schedule:
        return False
    for limit in (rule.source_user, rule.hip_profiles, rule.category):
        if limit and set(limit) != {"any"}:
            return False
    return True


def rule_base_matches(rule, req_action: str, req_application: set, req_source_zone: str, req_dest_zone: str) -> bool:
    """Zones, Application and Action must match exactly before a rule is
    even considered for duplicate/merge."""
    return (
        rule_is_plain(rule)
        and set(rule.fromzone or []) == {req_source_zone}
        and set(rule.tozone or []) == {req_dest_zone}
        and set(rule.application or []) == req_application
        and (rule.action or "").strip().lower() == req_action
    )


def find_matching_rule(existing_rules: list, req: dict, resolved_service_names: list, req_application_list: list, req_source_zone: str, req_dest_zone: str, req_sources: list, req_dests: list, address_book, consolidate_fields: list):
    """Returns (rule, merge_field):
        (rule, None)     - DUPLICATE: rule already covers the request
        (rule, "source") - same Destination + Service + App + Action + zones,
                           so the new Source is added to this rule
        (None, None)     - a genuine difference, so this gets its own rule"""
    req_action = str(req.get("Action") or "").strip().lower()
    req_application = set(req_application_list)
    req_services = set(resolved_service_names)

    candidates = [r for r in existing_rules if rule_base_matches(r, req_action, req_application, req_source_zone, req_dest_zone)]

    # Pass 1: is this traffic already fully allowed by some candidate?
    for rule in candidates:
        if (
            address_book.covers(rule.source, req_sources)
            and address_book.covers(rule.destination, req_dests)
            and covers(rule.service, req_services)
        ):
            return rule, None

    def field_equal(rule, field: str) -> bool:
        if field == "source":
            return address_book.same(rule.source, req_sources)
        if field == "destination":
            return address_book.same(rule.destination, req_dests)
        return set(rule.service or []) == req_services

    # Pass 2: exactly one allowed field differs, the other two are EXACTLY equal.
    requested_any = {"source": "any" in req_sources, "destination": "any" in req_dests, "service": "any" in req_services}
    for field in consolidate_fields:
        if requested_any[field]:
            continue  # never widen an existing rule to 'any'
        others = [f for f in MERGEABLE_FIELDS if f != field]
        for rule in candidates:
            if not all(field_equal(rule, f) for f in others):
                continue
            if field == "service" and "application-default" in (set(rule.service or []) | req_services):
                continue  # PAN-OS can't mix application-default with ports
            return rule, field

    return None, None


# --- STEP 3 (no-match branch): checking for shadowing ----------------------

def check_shadowing(existing_rules: list, req: dict, resolved_service_names: list, req_application_list: list, req_source_zone: str, req_dest_zone: str, req_sources: list, req_dests: list, address_book, before_rule=None):
    """Finds an earlier rule that matches all of this request's traffic but with
    a DIFFERENT action. With before_rule, only rules above it are checked (the
    request would land in that rule). Returns that rule or None."""
    req_service = set(resolved_service_names)
    req_application = set(req_application_list)
    req_action = str(req.get("Action") or "").strip().lower()

    for rule in existing_rules:
        if rule is before_rule:
            return None
        rule_action = (rule.action or "").strip().lower()
        if rule_action == req_action or not rule_is_plain(rule):
            continue
        if (
            covers(rule.fromzone, {req_source_zone})
            and address_book.covers(rule.source, req_sources)
            and covers(rule.tozone, {req_dest_zone})
            and address_book.covers(rule.destination, req_dests)
            and covers(rule.service, req_service)
            and covers(rule.application, req_application)
        ):
            return rule
    return None


# --- Building the new-rule name -------------------------------------------

def make_rule_name(req: dict, dest_zone: str, taken_names: set) -> str:
    """Tag + Destination Zone + Action, de-duplicated with a counter."""
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
    """Replaces 'application-default' in the Application field with 'any'.
    Returns (normalized_list, note_or_None)."""
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


def _with_notes(details: str, notes: list) -> str:
    return details + "".join(f" Note: {note}." for note in notes)


def process_request(req: dict, existing_rules: list, taken_names: set, rulebase, fw, existing_services_by_name: dict, known_tag_names: set, address_book, virtual_routers_to_check: list, interface_zone_cache: dict, ip_zone_cache: dict, route_cache: dict, consolidate_fields: list, apply_changes: bool) -> dict:
    """Runs one Request-sheet row through the full pipeline. Decides first and
    collects device changes in `actions`, so a duplicate or a refused row leaves
    no stray objects behind. Returns a result dict for the Implementation sheet."""
    result = dict(req)
    result["Timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Normalize + self-consolidate once, so every step uses the same form.
    req_source_list, source_names = parse_address_cell(req.get("Source"))
    req_dest_list, dest_names = parse_address_cell(req.get("Destination"))
    source_group = str(req.get("Source Group") or "").strip()
    dest_group = str(req.get("Destination Group") or "").strip()
    req_application_list, application_note = normalize_application_list(split_values(req.get("Application")) or ["any"])
    raw_service_values, policy_notes, policy_problems = apply_application_id_policy(
        req, req_application_list, build_raw_service_values(req.get("Service"), req.get("Destination Port"))
    )
    notes = list(policy_notes)
    if application_note:
        notes.append(application_note)

    # A malformed IP must be reported as such, not as a missing route.
    malformed = [a for a in req_source_list + req_dest_list
                 if a not in address_book.objects and a not in address_book.groups
                 and IP_LIKE_PATTERN.match(a) and to_networks(a) is None]
    if malformed:
        result["Rule Name"] = ""
        result["Outcome"] = "Validation error"
        result["Details"] = f"{', '.join(malformed)} isn't a valid IP, CIDR or full IP range"
        print(f"        FAILED: {result['Details']}")
        return result

    # --- STEP 0: Resolve zones from routing ---
    print("  [1/5] Resolving zones from routing...")
    source_zone, source_zone_problems = resolve_zone_for_list(
        fw, req_source_list, virtual_routers_to_check, address_book, interface_zone_cache, ip_zone_cache, route_cache
    )
    dest_zone, dest_zone_problems = resolve_zone_for_list(
        fw, req_dest_list, virtual_routers_to_check, address_book, interface_zone_cache, ip_zone_cache, route_cache
    )
    all_zone_problems = [f"Source: {p}" for p in source_zone_problems] + [f"Destination: {p}" for p in dest_zone_problems]
    print(f"        Source zone: {source_zone or 'UNRESOLVED'}, Destination zone: {dest_zone or 'UNRESOLVED'}")

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
    problems = (
        all_zone_problems + policy_problems
        + validate_row(req, req_source_list, req_dest_list, raw_service_values, address_book, existing_services_by_name)
        + name_problems(source_names, address_book) + name_problems(dest_names, address_book)
    )
    if problems:
        result["Rule Name"] = ""
        result["Outcome"] = "Validation error"
        result["Details"] = "; ".join(problems)
        print(f"        FAILED: {result['Details']}")
        return result

    resolved_service_names, services_to_create = resolve_service_names(raw_service_values, existing_services_by_name)

    # --- STEP 2: Check existing rules ---
    print("  [3/5] Checking existing rules...")
    matched_rule, merge_field = find_matching_rule(
        existing_rules, req, resolved_service_names, req_application_list,
        source_zone, dest_zone, req_source_list, req_dest_list, address_book, consolidate_fields,
    )

    # --- STEP 3: Duplicate / merge / shadowing ---
    print("  [4/5] Checking for duplicates/merge/shadowing...")
    shadow_rule = None
    if matched_rule is None or merge_field is not None:
        shadow_rule = check_shadowing(
            existing_rules, req, resolved_service_names, req_application_list, source_zone, dest_zone,
            req_source_list, req_dest_list, address_book, before_rule=matched_rule,
        )

    actions = []
    new_rule = None

    if matched_rule is not None and merge_field is None:
        result["Rule Name"] = matched_rule.name
        result["Outcome"] = "Duplicate - already exists"
        result["Details"] = _with_notes(f"Rule '{matched_rule.name}' already covers this exact request - nothing to do.", notes)
    elif shadow_rule is not None:
        result["Rule Name"] = ""
        result["Outcome"] = "Shadow conflict - not created"
        result["Details"] = _with_notes(
            f"Existing rule '{shadow_rule.name}' (action={shadow_rule.action}) already matches this traffic "
            f"and sits earlier in the rulebase - this request would never be reached. "
            f"Not changing anything - review rule order manually.", notes
        )
    elif matched_rule is not None:
        if merge_field == "service":
            merged_values, changes = merge_service_names(list(matched_rule.service or []), resolved_service_names)
            plan_service_objects(services_to_create, existing_services_by_name, fw, actions, notes)
            matched_rule.service = merged_values
            actions.append(lambda r=matched_rule: r.update("service"))
            problem = None
        else:
            new_values = req_source_list if merge_field == "source" else req_dest_list
            new_names = source_names if merge_field == "source" else dest_names
            group_name = source_group if merge_field == "source" else dest_group
            changes, problem = plan_address_merge(
                address_book, matched_rule, merge_field, new_values, new_names, group_name, existing_rules, actions, notes
            )
        if problem:
            result["Rule Name"] = ""
            result["Outcome"] = "Validation error"
            result["Details"] = problem
        else:
            label = {"source": "Source", "destination": "Destination", "service": "Service/Port"}[merge_field]
            result["Rule Name"] = matched_rule.name
            result["Outcome"] = "Merged into existing rule"
            result["Details"] = _with_notes(f"Consolidated into rule '{matched_rule.name}'. Updated {label}: " + "; ".join(changes) + ".", notes)
    else:
        group_problems = [
            p for p in (
                group_column_problem(address_book, source_group, req_source_list, None, "source", existing_rules),
                group_column_problem(address_book, dest_group, req_dest_list, None, "destination", existing_rules),
            ) if p
        ]
        if group_problems:
            result["Rule Name"] = ""
            result["Outcome"] = "Validation error"
            result["Details"] = "; ".join(group_problems)
        else:
            new_name = make_rule_name(req, dest_zone, taken_names)
            taken_names.add(new_name)
            tag_values = split_values(req.get("Tag"))
            base_name = tag_values[0] if tag_values else new_name

            plan_service_objects(services_to_create, existing_services_by_name, fw, actions, notes)
            resolved_tag_names = plan_tags(tag_values, known_tag_names, fw, actions, notes)
            rule_sources = prepare_address_entries(address_book, req_source_list, source_names, source_group, "SRC", base_name, actions, notes)
            rule_dests = prepare_address_entries(address_book, req_dest_list, dest_names, dest_group, "DST", base_name, actions, notes)

            new_rule = SecurityRule(
                name=new_name,
                fromzone=[source_zone],
                tozone=[dest_zone],
                source=rule_sources,
                destination=rule_dests,
                service=resolved_service_names,
                application=req_application_list,
                action=str(req.get("Action") or "").strip().lower(),
                tag=resolved_tag_names,
            )

            def push_rule(rule=new_rule):
                rulebase.add(rule)
                rule.create()
            actions.append(push_rule)

            result["Rule Name"] = new_name
            result["Outcome"] = "Created new rule"
            result["Details"] = _with_notes(
                f"No rule could be reused, created '{new_name}' (Source Zone: {source_zone}, Destination Zone: {dest_zone}, "
                f"Application: {', '.join(req_application_list)}, Service: {', '.join(resolved_service_names)}).", notes
            )
            # In-memory append is unconditional so a dry run simulates the batch.
            existing_rules.append(new_rule)

    # --- STEP 4: Show proposed change / STEP 5: apply ---
    if apply_changes:
        try:
            for action in actions:
                action()
        except Exception as e:
            result["Outcome"] = "Apply error"
            result["Details"] = f"The firewall rejected this change: {e}. Planned: {result.get('Details')}"

    print(f"  [5/5] Proposed change: {result['Outcome']} - {result['Details']}")
    return result


# --- Writing the Implementation sheet -------------------------------------

def write_results(excel_path: Path, sheet_name: str, results: list):
    wb = openpyxl.load_workbook(excel_path)

    if sheet_name in wb.sheetnames:
        del wb[sheet_name]
    ws = wb.create_sheet(sheet_name)

    columns = REQUEST_COLUMNS + ["Rule Name", "Outcome", "Details", "Timestamp"]
    ws.append(columns)
    for result in results:
        ws.append([result.get(col, "") for col in columns])

    wb.save(excel_path)


# --- Main ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Validate and push Palo Alto security policies from an Excel sheet (firewall + credentials from AWX).")
    parser.add_argument("--excel", default=None, help="Path to the Excel file (default: excel_path from paloalto_config.json)")
    parser.add_argument("--request-sheet", default=None, help="Sheet name with the requested policies")
    parser.add_argument("--implementation-sheet", default=None, help="Sheet name to write results to")
    parser.add_argument("--apply", action="store_true", default=None, help="Actually create/update rules on the firewall")
    parser.add_argument("--commit", action="store_true", default=None, help="Commit the candidate config after applying")
    args = parser.parse_args()

    config = load_config()
    connection = load_awx_connection()

    excel_path = Path(args.excel if args.excel is not None else config["excel_path"])
    request_sheet = args.request_sheet if args.request_sheet is not None else config["request_sheet"]
    implementation_sheet = args.implementation_sheet if args.implementation_sheet is not None else config["implementation_sheet"]
    apply_changes = args.apply if args.apply is not None else config["apply"]
    do_commit = args.commit if args.commit is not None else config["commit"]

    if not excel_path.is_absolute():
        excel_path = get_base_dir() / excel_path

    print(f"Excel file: {excel_path}")
    if not excel_path.exists():
        print(f"ERROR: Excel file not found at {excel_path}")
        sys.exit(1)

    if do_commit and not apply_changes:
        print("NOTE: 'commit' is on but 'apply' is off - nothing to commit. Ignoring commit for this run.")
        do_commit = False

    print(f"Connecting to firewall {connection['hostname']} (from AWX inventory)...")
    fw, rulebase, existing_rules, existing_services_by_name, known_tag_names, zone_names, address_book, virtual_routers_to_check = connect_to_firewall(connection, config)
    taken_names = {rule.name for rule in existing_rules}
    interface_zone_cache = {}
    ip_zone_cache = {}
    route_cache = {}
    print(f"Found {len(existing_rules)} existing security rule(s) on the firewall.")
    print(f"Found {len(existing_services_by_name)} existing service object(s), {len(known_tag_names)} tag(s), {len(zone_names)} zone(s), {len(address_book.objects)} address object(s), {len(address_book.groups)} address group(s) on the firewall.")
    print(f"Checking virtual router(s) for zone-from-routing lookups: {', '.join(virtual_routers_to_check)}")

    print(f"Reading requests from '{request_sheet}' sheet...")
    requests = read_requests(excel_path, request_sheet)
    print(f"Found {len(requests)} request row(s).")

    print(f"\nMODE: {'APPLY' if apply_changes else 'DRY RUN'}" + (" + COMMIT" if do_commit else ""))
    if not apply_changes:
        print("No changes will be made on the firewall.\n")
    else:
        print()

    results = []
    for i, req in enumerate(requests, start=1):
        print(f"Row {i}:")
        result = process_request(
            req, existing_rules, taken_names, rulebase, fw,
            existing_services_by_name, known_tag_names,
            address_book, virtual_routers_to_check,
            interface_zone_cache, ip_zone_cache, route_cache,
            config["consolidate_fields"],
            apply_changes=apply_changes,
        )
        results.append(result)

    print(f"\nWriting results to '{implementation_sheet}' sheet in {excel_path}...")
    write_results(excel_path, implementation_sheet, results)

    apply_errors = sum(1 for r in results if r["Outcome"] == "Apply error")

    if apply_errors and do_commit:
        print("NOT committing: the firewall rejected at least one change. Review the candidate config.")
    elif apply_changes and do_commit:
        print("Committing candidate config to the firewall (this can take a minute)...")
        commit_result = fw.commit(sync=True)
        print(f"Commit result: {commit_result}")
    elif apply_changes:
        print("Changes were applied to the CANDIDATE config but NOT committed.")

    merged = sum(1 for r in results if r["Outcome"] == "Merged into existing rule")
    created = sum(1 for r in results if r["Outcome"] == "Created new rule")
    duplicates = sum(1 for r in results if r["Outcome"] == "Duplicate - already exists")
    shadowed = sum(1 for r in results if r["Outcome"] == "Shadow conflict - not created")
    no_route = sum(1 for r in results if r["Outcome"] == "Could not implement - no specific route found")
    invalid = sum(1 for r in results if r["Outcome"] == "Validation error")
    print(f"\nSummary: {merged} merged, {created} created, {duplicates} duplicate, {shadowed} shadow conflict(s), {no_route} no-route, {invalid} validation error(s), {apply_errors} apply error(s).")

    if apply_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
    # Pause only when a human is at a console (double-click / .exe).
    # AWX has no interactive stdin - input() there would crash the job.
    if sys.stdin is not None and sys.stdin.isatty():
        input("\nDone. Press Enter to close this window...")
