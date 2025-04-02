# email-security-analyzer

<b>Project Overview:</b></br>
The Email Security Analyzer is a Python-based tool designed to evaluate email security, verify domain authenticity, and detect potential phishing threats. This command-line application integrates with multiple security APIs to provide a robust analysis of email headers, domain information, and security posture.

<b>Problem Statement:</b></br>
Email remains one of the primary attack vectors for phishing, business email compromise, and malware distribution. Security analysts and IT professionals need efficient tools to quickly assess email legitimacy and identify suspicious indicators. Existing commercial solutions are often expensive or lack comprehensive analysis in a single tool.

<b>Solution:</b></br>
<ul>I developed a modular Python application that consolidates multiple security checks into a single, easy-to-use interface. The tool offers four primary functions:</br>
<li>Header Analysis: Extracts and validates sender information, SPF/DMARC records, return path matching, and domain reputation.</li></br>
<li>Domain Intelligence: Retrieves domain registration details, identifies ownership information, and verifies legitimacy based on registration data.</li></br>
<li>Blocklist Checking: Queries multiple reputation databases to determine if domains or IP addresses are associated with malicious activity.</li></br>
<li>Authentication Verification: Assesses email authentication mechanisms like SPF and DMARC to verify sender legitimacy.</li></br>
</ul>

<b>Technical Implementation:</b></br>
<ul>The application was built using Python 3.x and incorporates:</br>
<li>API Integration: Connected to multiple security services (VirusTotal, AbuseIPDB, WhoisXML, Google Custom Search) through their REST APIs.</li></br>
</li>Modular Architecture: Designed with separate classes for each analysis type, facilitating maintenance and future expansion.</li></br>
</li>Regex Pattern Matching: Implemented sophisticated pattern recognition to extract key information from email headers and WHOIS data.</li></br>
</li>DNS Querying: Directly queries DNS records to validate SPF and DMARC configurations.</li></br>
</li>Command-Line Interface: Created an intuitive menu-driven interface with both interactive and direct command modes.</li></br>
</ul>ul>  
  
<b>Results:</b></br>
<ul>The Email Security Analyzer delivers:</br>
<li>Full security assessments in seconds rather than minutes of manual checking</br>
<li>Integration of multiple security data sources in a single tool</li></br>
<li>Detailed domain intelligence for informed security decisions</li></br>
<li>Clear indicators of potential phishing or fraudulent emails</li></br>
</ul>
The tool has proven particularly valuable for rapid triage of suspicious emails and initial threat hunting, which helps prioritize response efforts more effectively.</br>

<ul><b>Technologies Used:</b></br>
<li>Python 3.x</li></br>
<li>Requests library for API communication</li></br>
<li>DNSPython for DNS record validation</li></br>
<li>Email parsing libraries</li></br>
<li>Regular expressions for pattern matching</li></br>
<li>Command-line argument parsing</li></br>
<li>Multiple security APIs (VirusTotal, AbuseIPDB, WhoisXML, Google Custom Search)</li></br>
</ul>

<ul><b>Future Enhancements:</b></br>
<li>Potential future improvements include:</br>
<li>Email attachment analysis capabilities</br>
<li>URL scanning and reputation checking</br>
<li>Web-based interface option</br>
</ul>

This project demonstrates my ability to create practical security tools that combine multiple data sources, implement complex pattern analysis, and deliver actionable security intelligence through clean, maintainable code.

