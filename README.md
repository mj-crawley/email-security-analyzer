# email-security-analyzer

<b>Project Overview:</b></br>
The Email Security Analyzer is a Python-based tool designed to evaluate email security, verify domain authenticity, and detect potential phishing threats. This command-line application integrates with multiple security APIs to provide a robust analysis of email headers, domain information, and security posture.

<b>Problem Statement:</b></br>
Email remains one of the primary attack vectors for phishing, business email compromise, and malware distribution. Security analysts and IT professionals need efficient tools to quickly assess email legitimacy and identify suspicious indicators. Existing commercial solutions are often expensive or lack comprehensive analysis in a single tool.

<b>Solution:</b></br>
I developed a modular Python application that consolidates multiple security checks into a single, easy-to-use interface. The tool offers four primary functions:</br>
<ul><li>Header Analysis: Extracts and validates sender information, SPF/DMARC records, return path matching, and domain reputation.</li>
<li>Domain Intelligence: Retrieves domain registration details, identifies ownership information, and verifies legitimacy based on registration data.</li>
<li>Blocklist Checking: Queries multiple reputation databases to determine if domains or IP addresses are associated with malicious activity.</li>
<li>Authentication Verification: Assesses email authentication mechanisms like SPF and DMARC to verify sender legitimacy.</li>
</ul>

<b>Technical Implementation:</b></br>
The application was built using Python 3.x and incorporates:</br>
<ul><li>API Integration: Connected to multiple security services (VirusTotal, AbuseIPDB, WhoisXML, Google Custom Search) through their REST APIs.</li>
<li>Modular Architecture: Designed with separate classes for each analysis type, facilitating maintenance and future expansion.</li>
<li>Regex Pattern Matching: Implemented sophisticated pattern recognition to extract key information from email headers and WHOIS data.</li>
<li>DNS Querying: Directly queries DNS records to validate SPF and DMARC configurations.</li>
<li>Command-Line Interface: Created an intuitive menu-driven interface with both interactive and direct command modes.</li>
</ul>
  
<b>Results:</b></br>
The Email Security Analyzer delivers:</br>
<ul><li>Full security assessments in seconds rather than minutes of manual checking
<li>Integration of multiple security data sources in a single tool</li>
<li>Detailed domain intelligence for informed security decisions</li>
<li>Clear indicators of potential phishing or fraudulent emails</li>
</ul>

The tool has proven particularly valuable for rapid triage of suspicious emails and initial threat hunting, which helps prioritize response efforts more effectively.</br></br>

<b>Technologies Used:</b></br>
<ul><li>Python 3.x</li>
<li>Requests library for API communication</li>
<li>DNSPython for DNS record validation</li>
<li>Email parsing libraries</li>
<li>Regular expressions for pattern matching</li>
<li>Command-line argument parsing</li>
<li>Multiple security APIs (VirusTotal, AbuseIPDB, WhoisXML, Google Custom Search)</li>
</ul>

<b>Future Enhancements:</b></br>
Potential future improvements include:
<ul><li>Email attachment analysis capabilities
<li>URL scanning and reputation checking
<li>Web-based interface option
</li></ul>

This project demonstrates my ability to create practical security tools that combine multiple data sources, implement complex pattern analysis, and deliver actionable security intelligence through clean, maintainable code.

