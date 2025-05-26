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

