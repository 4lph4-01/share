import argparse
from utils import run_test
from report_generator import generate_report

def main():
    parser = argparse.ArgumentParser(description="DHCP Resilience Tester (Ethical Use Only)")
    parser.add_argument("--interface", required=True, help="Network interface (e.g., eth0)")
    parser.add_argument("--count", type=int, default=100, help="Number of DHCPDISCOVER packets to send")
    parser.add_argument("--mode", choices=["simulation", "live"], default="simulation", help="Test mode")
    parser.add_argument("--report", action="store_true", help="Generate report at the end")

    print("\n[!] WARNING: Authorized use only. Misuse may be illegal.\n")
    args = parser.parse_args()

    log = run_test(args.interface, args.count, args.mode)

    if args.report:
        generate_report(log)

if __name__ == "__main__":
    main()

