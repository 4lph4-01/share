######################################################################################################################################################################################################################
# Part of the framework for DHCP resilience/starvation testing. By 41ph4-01, and our community. Note: Be mindful of the scope of work, & rules of engagement.
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software 
# without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons 
# to whom the Software is furnished to do so, subject to the following conditions: The above copyright notice and this permission notice shall be included in all copies or substantial 
# portions of the Software.
# THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE 
# AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, 
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
######################################################################################################################################################################################################################

def generate_report(log):
    print("[+] Generating report...")

    summary = log["summary"]
    report_lines = [
        "---- DHCP RESILIENCE REPORT ----",
        f"Timestamp: {log['timestamp']}",
        f"Interface: {log['interface']}",
        f"Mode: {log['mode']}",
        "",
        f"Packets Sent: {summary['sent']}",
        f"DHCPOFFERs Received: {summary['received']}",
        f"Response Ratio: {summary['ratio']:.2%}",
        f"Test Duration: {summary['duration_sec']:.2f} seconds",
        f"Conclusion: {summary['resilience']}",
        "",
        "--- MAC Addresses Used ---",
        *log["macs"],
        "",
        "--- Offer Response Times (s) ---",
        *[f"{t:.3f}" for t in log["response_times"]],
        ""
    ]

    output = "\n".join(report_lines)
    report_path = f"dhcp_resilience_tester/logs/report_{log['timestamp'].replace(':', '_')}.txt"
    with open(report_path, "w") as f:
        f.write(output)

    print(f"[+] Report saved: {report_path}")

