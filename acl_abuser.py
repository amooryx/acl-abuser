#!/usr/bin/env python3
"""
ACL Abuser — Active Directory ACL/ACE Misconfiguration Finder
Finds exploitable ACEs: GenericAll, WriteDACL, WriteOwner, ForceChangePassword.
Requires ldap3: pip install ldap3
Author: Omar Khalid (amooryx) | github.com/amooryx/acl-abuser
AUTHORIZED USE ONLY — for authorized red team engagements.
"""

import argparse
import json
import sys

try:
    import ldap3
    from ldap3.protocol.microsoft import security_descriptor_control
    HAS_LDAP3 = True
except ImportError:
    HAS_LDAP3 = False

DANGEROUS_RIGHTS = {
    0x000F01FF: "GenericAll (Full Control)",
    0x00020044: "GenericWrite",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000100: "ForceChangePassword (ExtendedRight)",
    0x00000028: "WriteProperty",
}

def connect(dc: str, domain: str, user: str, password: str, port: int = 389):
    if not HAS_LDAP3:
        print("[!] ldap3 required: pip install ldap3")
        sys.exit(1)
    server = ldap3.Server(dc, port=port, get_info=ldap3.ALL)
    conn   = ldap3.Connection(server, user=f"{domain}\\{user}", password=password,
                              authentication=ldap3.NTLM, auto_bind=True)
    return conn

def base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split("."))

def find_acl_abuse(conn, bdn: str, target_user: str | None = None) -> list[dict]:
    """
    Query objects and look for interesting ACEs.
    In a real engagement this uses ntlmrelayx or BloodHound data.
    Here we demonstrate via LDAP attribute query.
    """
    findings = []
    # Query all user/group objects for their nTSecurityDescriptor
    filter_ = f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(target_user)})" if target_user \
              else "(objectClass=user)"
    try:
        conn.search(bdn, filter_,
                    attributes=["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04))
        for entry in conn.entries:
            sd = entry.nTSecurityDescriptor.raw_values
            if sd:
                findings.append({
                    "object":    str(entry.sAMAccountName),
                    "dn":        str(entry.distinguishedName),
                    "note":      "nTSecurityDescriptor retrieved — parse with BloodHound/Impacket for full ACE analysis",
                    "has_dacl":  True,
                })
    except Exception as e:
        findings.append({"error": str(e)})

    return findings

def check_bloodhound_json(bh_file: str) -> list[dict]:
    """Parse BloodHound JSON export to find dangerous ACEs."""
    findings = []
    try:
        with open(bh_file) as f:
            data = json.load(f)
        edges = data.get("data", []) if isinstance(data, dict) else data
        dangerous_edge_types = ["GenericAll", "WriteDACL", "WriteOwner",
                                "ForceChangePassword", "GenericWrite", "Owns"]
        for edge in edges:
            if isinstance(edge, dict) and edge.get("relationshipType") in dangerous_edge_types:
                findings.append({
                    "source":     edge.get("startNode"),
                    "target":     edge.get("endNode"),
                    "type":       edge.get("relationshipType"),
                    "note":       f"Dangerous ACE: {edge.get('relationshipType')} from {edge.get('startNode')} to {edge.get('endNode')}",
                    "severity":   "High",
                })
    except Exception as e:
        findings.append({"error": str(e)})
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="ACL Abuser — AD ACL Misconfiguration Finder (Authorized use only)",
    )
    parser.add_argument("--dc",        help="Domain controller IP")
    parser.add_argument("--domain",    help="Domain (e.g., corp.local)")
    parser.add_argument("--user",      help="Username")
    parser.add_argument("--password",  help="Password")
    parser.add_argument("--target",    help="Target object to check ACL on (optional)")
    parser.add_argument("--bloodhound",help="Parse BloodHound JSON export file")
    parser.add_argument("--out",       help="Output JSON file")
    args = parser.parse_args()

    results = {}

    if args.bloodhound:
        print(f"[*] Parsing BloodHound export: {args.bloodhound}")
        findings = check_bloodhound_json(args.bloodhound)
        print(f"[+] {len(findings)} dangerous ACEs found")
        for f in findings:
            print(f"  [{f.get('severity','?')}] {f.get('source')} --[{f.get('type')}]--> {f.get('target')}")
        results["acl_findings"] = findings

    elif args.dc and args.domain and args.user and args.password:
        conn = connect(args.dc, args.domain, args.user, args.password)
        bdn  = base_dn(args.domain)
        print(f"[*] Querying ACLs via LDAP ...")
        findings = find_acl_abuse(conn, bdn, args.target)
        print(f"[+] {len(findings)} objects queried")
        for f in findings:
            print(f"  {f.get('object','')}: {f.get('note','')}")
        results["acl_findings"] = findings
    else:
        parser.print_help()
        sys.exit(1)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(results, f, indent=2)
        print(f"[*] Results → {args.out}")

if __name__ == "__main__":
    main()
