Project Title

Network Incident Analysis — MirrorBlast Command & Control Activity

Objective

To investigate a network security alert related to suspected Command and Control (C2) activity, confirm whether the alert was a true positive, extract relevant artifacts, and determine the origin and behavior of the threat.

Process

After receiving an alert indicating possible malware activity, the provided PCAP file was opened in Brim for an initial overview of the network traffic.

By filtering events and IP connections, the traffic related to the Malware Command and Control Activity signature was identified. The source and destination IP addresses were extracted and analyzed using VirusTotal, which revealed attribution to the TA505 threat group and the MirrorBlast malware family.

Further inspection of HTTP traffic was carried out in Wireshark. Using the Follow HTTP Stream function, the User-Agent associated with MirrorBlast activity was identified, along with the filenames of downloaded payloads and their storage directories.

Through Network Miner, the downloaded artifacts — including MSI installer packages and executable files — were extracted. Based on timestamps and connection patterns, the attack chain was reconstructed, showing the download, execution, and installation of additional malicious components in system directories.

Additional IP addresses linked to the same MirrorBlast campaign were discovered and verified via VirusTotal. All Indicators of Compromise (IOCs) — including IPs, domains, filenames, and file paths — were documented for integration into SIEM and threat detection systems.

Results

Confirmed true positive C2 activity.

Identified multiple IP addresses tied to the MirrorBlast malware and TA505 group.

Determined file storage paths and the creation of secondary malicious binaries.

Extracted artifacts for sandbox and forensic analysis.

Conclusion

The investigation confirmed active C2 communication and the download of malicious files associated with MirrorBlast. All indicators have been recorded and can be used for immediate blocking, correlation in future alerts, and enhanced detection rules across the organization’s monitoring systems.
