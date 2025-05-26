# DHCP Resilience Tester

Fully functional resilience testing tool. This tool is for authorised use only. Performing unauthorised tests on networks is illegal and unethical.

# DHCP Resilience Tester

This tool simulates DHCP starvation attempts to evaluate DHCP server resilience. Use the live testing with caution.

# Includes

Simulation and live test modes,
MAC address spoofing and logging,
Offer response timing and evaluation,
Clear resilience grading (Resilient / Partially / Vulnerable), and
Human-readable reports with saved logs

## Usage
```bash
python dhcp_tester.py --interface eth0 --count 100 --mode simulation --report



