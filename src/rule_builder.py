import ipaddress
import json
import os
import click

def validate_action(action):
    if not action:
        raise ValueError("Action is required")
    act = action.strip().upper()
    if act not in ["ALERT", "BLOCK"]:
        raise ValueError("Action must be either ALERT or BLOCK")
    return act

def validate_protocol(protocol):
    if not protocol:
        return None
    proto = protocol.strip()
    proto_lower = proto.lower()
    if proto_lower in ["tcp", "udp", "icmp"]:
        return proto_lower.upper()
    
    # Check if integer between 0 and 255
    try:
        val = int(proto)
        if 0 <= val <= 255:
            return val
    except ValueError:
        pass
    
    raise ValueError("Protocol must be TCP, UDP, ICMP or an integer 0-255")

def validate_ip(ip):
    if not ip:
        return None
    val = ip.strip()
    try:
        # strict=False allows matching CIDR subnets like 192.168.1.50/24
        ipaddress.ip_network(val, strict=False)
        return val
    except ValueError:
        raise ValueError("Invalid IP address or CIDR subnet syntax")

def validate_ports(ports):
    if not ports:
        return None
    val = str(ports).strip()
    
    # Range check (e.g. "80-90")
    if "-" in val:
        try:
            parts = val.split("-")
            if len(parts) != 2:
                raise ValueError
            start = int(parts[0].strip())
            end = int(parts[1].strip())
            if 0 < start <= 65535 and 0 < end <= 65535 and start <= end:
                return f"{start}-{end}"
        except ValueError:
            pass
        raise ValueError("Invalid port range (format: start-end, e.g. 80-90)")
        
    # List check (e.g. "80,443")
    elif "," in val:
        try:
            ports_list = [int(p.strip()) for p in val.split(",")]
            if all(0 < p <= 65535 for p in ports_list):
                return ",".join(str(p) for p in ports_list)
        except ValueError:
            pass
        raise ValueError("Invalid port list (format: port1,port2, e.g. 80,443)")
        
    # Single port check
    else:
        try:
            p = int(val)
            if 0 < p <= 65535:
                return p
        except ValueError:
            pass
        raise ValueError("Invalid port number (must be 1-65535)")


class InteractiveRuleBuilder:
    @staticmethod
    def prompt_rule():
        """
        Interactively prompts the user to create a new rule with real-time validation.
        """
        click.secho("\n=== Interactive DPI Rule Builder ===", fg="cyan", bold=True)
        
        # 1. Rule ID
        rule_id = ""
        while not rule_id:
            rule_id = click.prompt("Enter Rule ID (e.g. block_facebook)")
            if not rule_id.strip():
                click.secho("Rule ID cannot be empty", fg="red")
                rule_id = ""

        # 2. Action
        action = None
        while action is None:
            val = click.prompt("Action (ALERT / BLOCK)", default="ALERT")
            try:
                action = validate_action(val)
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 3. Protocol
        protocol = None
        while True:
            val = click.prompt("Protocol (TCP / UDP / ICMP / empty for any)", default="", show_default=False)
            if not val:
                break
            try:
                protocol = validate_protocol(val)
                break
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 4. Source IP
        src_ip = None
        while True:
            val = click.prompt("Source IP/CIDR (e.g. 192.168.1.0/24 / empty for any)", default="", show_default=False)
            if not val:
                break
            try:
                src_ip = validate_ip(val)
                break
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 5. Source Port
        src_port = None
        while True:
            val = click.prompt("Source Port/Range/List (e.g. 80, 80-90, 80,443 / empty for any)", default="", show_default=False)
            if not val:
                break
            try:
                src_port = validate_ports(val)
                break
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 6. Destination IP
        dst_ip = None
        while True:
            val = click.prompt("Destination IP/CIDR (empty for any)", default="", show_default=False)
            if not val:
                break
            try:
                dst_ip = validate_ip(val)
                break
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 7. Destination Port
        dst_port = None
        while True:
            val = click.prompt("Destination Port/Range/List (empty for any)", default="", show_default=False)
            if not val:
                break
            try:
                dst_port = validate_ports(val)
                break
            except ValueError as e:
                click.secho(f"Error: {str(e)}", fg="red")

        # 8. Domain SNI
        domain = click.prompt("Domain/SNI Pattern (e.g. *.facebook.com / empty for any)", default="", show_default=False)
        domain = domain.strip() if domain else None

        # Build rule dictionary
        rule = {
            "rule_id": rule_id,
            "action": action
        }
        if protocol is not None:
            rule["protocol"] = protocol
        if src_ip is not None:
            rule["src_ip"] = src_ip
        if src_port is not None:
            rule["src_port"] = src_port
        if dst_ip is not None:
            rule["dst_ip"] = dst_ip
        if dst_port is not None:
            rule["dst_port"] = dst_port
        if domain is not None:
            rule["domain"] = domain

        return rule

    @staticmethod
    def save_rule_to_file(rule, filepath):
        """
        Saves a rule dictionary to a JSON rules file, appending to it if it already exists.
        """
        rules_list = []
        if os.path.exists(filepath):
            try:
                with open(filepath, "r") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        rules_list = data
            except Exception:
                click.secho(f"Warning: Could not parse existing file {filepath}. Overwriting with new rule.", fg="yellow")

        # Append new rule
        rules_list.append(rule)

        with open(filepath, "w") as f:
            json.dump(rules_list, f, indent=2)
            
        click.secho(f"\n✔ Successfully saved rule '{rule['rule_id']}' to {filepath}", fg="green", bold=True)
