import ipaddress
import json
import os
import re
from logger import get_logger

logger = get_logger("RulesEngine")

class Rule:
    def __init__(self, rule_id, action, protocol=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, domain=None, payload_pattern=None):
        self.rule_id = rule_id
        self.action = action.upper()  # ALERT, BLOCK
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.domain = domain
        self.payload_pattern = payload_pattern
        self.compiled_pattern = None
        if payload_pattern:
            try:
                # If it's a string pattern, encode to bytes. If already bytes, use it directly.
                pattern_bytes = payload_pattern.encode('utf-8') if isinstance(payload_pattern, str) else payload_pattern
                self.compiled_pattern = re.compile(pattern_bytes, re.IGNORECASE)
            except Exception as e:
                logger.error(f"Failed to compile regex payload pattern '{payload_pattern}': {str(e)}")

    def matches(self, src_ip, src_port, dst_ip, dst_port, protocol, domain=None, payload=b''):
        """
        Evaluates if the packet/flow parameters match this rule.
        Note that direction is bidirectional, so we check both (src->dst) and (dst->src) matches.
        """
        # 1. Protocol Match
        if not self._match_protocol(protocol):
            return False

        # 2. Domain Match
        # If the rule defines a domain requirement, but no domain is provided yet,
        # we return False (or wait for flow SNI extraction).
        if self.domain and not self._match_domain(domain):
            return False

        # 3. Payload Match
        if self.payload_pattern:
            if not self.compiled_pattern or not payload:
                return False
            if not self.compiled_pattern.search(payload):
                return False

        # 4. IP and Port matches (bidirectional)
        # Check direct direction (src matches rule.src, dst matches rule.dst)
        direct_match = (
            self._match_ip(src_ip, self.src_ip) and
            self._match_port(src_port, self.src_port) and
            self._match_ip(dst_ip, self.dst_ip) and
            self._match_port(dst_port, self.dst_port)
        )
        if direct_match:
            return True

        # Check reverse direction (src matches rule.dst, dst matches rule.src)
        reverse_match = (
            self._match_ip(src_ip, self.dst_ip) and
            self._match_port(src_port, self.dst_port) and
            self._match_ip(dst_ip, self.src_ip) and
            self._match_port(dst_port, self.src_port)
        )
        return reverse_match

    def _match_protocol(self, protocol):
        if self.protocol is None:
            return True
        
        # Map strings to standard protocol numbers
        proto_map = {
            "tcp": 6,
            "udp": 17,
            "icmp": 1
        }
        
        target_proto = self.protocol
        if isinstance(target_proto, str):
            target_proto_lower = target_proto.lower()
            if target_proto_lower in proto_map:
                target_proto = proto_map[target_proto_lower]
            else:
                try:
                    target_proto = int(target_proto)
                except ValueError:
                    return False
        
        return protocol == target_proto

    def _match_ip(self, ip_val, rule_ip):
        if rule_ip is None:
            return True
        if ip_val is None:
            return False
        try:
            network = ipaddress.ip_network(rule_ip, strict=False)
            ip = ipaddress.ip_address(ip_val)
            return ip in network
        except ValueError:
            return False

    def _match_port(self, port_val, rule_port):
        if rule_port is None:
            return True
        if port_val is None or port_val == 0:
            return False

        # If it is integer
        if isinstance(rule_port, int):
            return port_val == rule_port

        # If it is string
        if isinstance(rule_port, str):
            rule_port = rule_port.strip()
            # Range check (e.g. "80-90")
            if "-" in rule_port:
                try:
                    parts = rule_port.split("-")
                    if len(parts) == 2:
                        return int(parts[0]) <= port_val <= int(parts[1])
                except ValueError:
                    return False
            # List check (e.g. "80,443")
            elif "," in rule_port:
                try:
                    ports = [int(p.strip()) for p in rule_port.split(",")]
                    return port_val in ports
                except ValueError:
                    return False
            # Single value
            else:
                try:
                    return port_val == int(rule_port)
                except ValueError:
                    return False

        return False

    def _match_domain(self, domain_val):
        if self.domain is None:
            return True
        if domain_val is None:
            return False

        rule_dom = self.domain.lower()
        test_dom = domain_val.lower()

        if rule_dom.startswith("*."):
            suffix = rule_dom[2:]
            return test_dom == suffix or test_dom.endswith("." + suffix)

        # Match exact domain or any of its subdomains (e.g. google.com matches www.google.com)
        return test_dom == rule_dom or test_dom.endswith("." + rule_dom)


class RulesEngine:
    def __init__(self):
        self.rules = []
        self.rules_filepath = None
        self.last_modified_time = 0.0

    def load_rules(self, rules_list):
        """Loads rules from a list of dicts/Rule objects."""
        self.rules = []
        for r in rules_list:
            if isinstance(r, Rule):
                self.rules.append(r)
            elif isinstance(r, dict):
                self.rules.append(Rule(
                    rule_id=r.get("rule_id"),
                    action=r.get("action", "ALERT"),
                    protocol=r.get("protocol"),
                    src_ip=r.get("src_ip"),
                    dst_ip=r.get("dst_ip"),
                    src_port=r.get("src_port"),
                    dst_port=r.get("dst_port"),
                    domain=r.get("domain"),
                    payload_pattern=r.get("payload_pattern")
                ))

    def load_rules_from_file(self, filepath):
        """Loads rules from a JSON config file."""
        if not os.path.exists(filepath):
            logger.error(f"Rules file not found: {filepath}")
            raise FileNotFoundError(f"Rules file not found: {filepath}")
        self.rules_filepath = filepath
        self.last_modified_time = os.path.getmtime(filepath)
        with open(filepath, "r") as f:
            data = json.load(f)
            if not isinstance(data, list):
                logger.error(f"Invalid rules format in {filepath}: not a list")
                raise ValueError("Rules file must contain a JSON list of rules")
            self.load_rules(data)
            logger.info(f"Loaded {len(self.rules)} rules from {filepath}")

    def check_and_reload(self):
        """
        Checks if the loaded rules file has been modified and reloads it if so.
        Returns True if rules were reloaded, False otherwise.
        """
        if not self.rules_filepath or not os.path.exists(self.rules_filepath):
            return False
        
        try:
            current_mtime = os.path.getmtime(self.rules_filepath)
            if current_mtime > self.last_modified_time:
                logger.info(f"Rules file {self.rules_filepath} modification detected. Reloading...")
                with open(self.rules_filepath, "r") as f:
                    data = json.load(f)
                    if not isinstance(data, list):
                        logger.error("Failed to hot-reload: config format not a list")
                        return False
                    self.load_rules(data)
                self.last_modified_time = current_mtime
                logger.info(f"Hot-reloaded {len(self.rules)} rules successfully")
                return True
        except Exception as e:
            logger.error(f"Exception during rules hot-reload: {str(e)}")
        return False

    def evaluate_packet(self, src_ip, src_port, dst_ip, dst_port, protocol, domain=None, payload=b''):
        """
        Evaluates details of a packet/flow.
        Returns the first matching Rule, or None.
        """
        logger.debug(f"Evaluating packet: {src_ip}:{src_port} <-> {dst_ip}:{dst_port} | Proto={protocol} | Domain={domain} | PayloadSize={len(payload)}")
        for rule in self.rules:
            if rule.matches(src_ip, src_port, dst_ip, dst_port, protocol, domain, payload):
                logger.info(f"Rule match: rule_id={rule.rule_id}, action={rule.action} for {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
                return rule
        return None

    def evaluate_flow(self, flow, payload=b''):
        """
        Evaluates a Flow object.
        Returns the first matching Rule, or None.
        """
        ip_a, port_a, ip_b, port_b, protocol = flow.flow_key
        # Domain can be either flow.sni or domain parsed from HTTP host
        return self.evaluate_packet(
            src_ip=ip_a,
            src_port=port_a,
            dst_ip=ip_b,
            dst_port=port_b,
            protocol=protocol,
            domain=flow.sni,
            payload=payload
        )

    def add_domain_block(self, domain: str):
        rule_id = f"BLOCK_{domain.upper().replace('.', '_')}"
        # Prevent duplicates
        if any(r.rule_id == rule_id for r in self.rules):
            return
        rule = Rule(
            rule_id=rule_id,
            action="BLOCK",
            domain=domain
        )
        self.rules.append(rule)

    def remove_domain_block(self, domain: str):
        rule_id = f"BLOCK_{domain.upper().replace('.', '_')}"
        self.rules = [r for r in self.rules if r.rule_id != rule_id]

