import boto3
from config import SENSITIVE_PORTS, PUBLIC_CIDR
from dns_tunneling import scan_dns_logs

ec2 = boto3.client("ec2")
elbv2 = boto3.client("elbv2")


def check_security_group_exposure():
    print("\n[+] Checking security groups for risky ingress rules...\n")

    response = ec2.describe_security_groups()

    for sg in response["SecurityGroups"]:
        for rule in sg.get("IpPermissions", []):
            if rule.get("FromPort") not in SENSITIVE_PORTS:
                continue

            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == PUBLIC_CIDR:
                    print(
                        f"[ALERT] {sg['GroupName']} allows "
                        f"port {rule['FromPort']} from the internet"
                    )


def check_public_load_balancers():
    print("\n[+] Checking for public-facing load balancers...\n")

    response = elbv2.describe_load_balancers()

    for lb in response["LoadBalancers"]:
        if lb["Scheme"] == "internet-facing":
            print(
                f"[INFO] Public LB detected: "
                f"{lb['LoadBalancerName']} ({lb['DNSName']})"
            )


def run_dns_tunneling_detection():
    """
    Simulated DNS log entries.
    In production, these would come from Route53 Resolver logs,
    SIEM exports, or packet inspection.
    """
    sample_dns_logs = [
        "normal.example.com",
        "dGhpcy1sb29rcy1lbmNvZGVk.bad-domain.com",
        "xj39dkf93jf9d8f9d8f9d8f.exfil.example.net",
        "login.company.internal",
    ]

    scan_dns_logs(sample_dns_logs)


def main():
    check_security_group_exposure()
    check_public_load_balancers()
    run_dns_tunneling_detection()
    print("\n[+] Drift and DNS analysis completed.\n")


if __name__ == "__main__":
    main()
