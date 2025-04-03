<h1>Instructions</h1>
<h2>Prerequisites</h2>
Before setting up the Email Security Analyzer, ensure you have:
Python 3.6 or higher installed
Internet access to download dependencies and make API calls
API keys from the required services (instructions below)

<h2>Step 1: Install Required Python Packages</h2>
Open a command prompt or terminal and run:
pip install requests dnspython

<h2>Step 2: Obtain Required API Keys</h2>
<ul>The tool requires the following API keys:
Google Custom Search API
Visit Google Cloud Console
Create a new project
Enable "Custom Search JSON API"
Create API credentials
Also create a search engine at Programmable Search Engine and note the Search Engine ID (cx) 
VirusTotal API
Register at VirusTotal
Find your API key in your account settings
AbuseIPDB API
Create an account at AbuseIPDB
Generate an API key in your account dashboard
WhoisXML API
Register at WhoisXML API
Get your API key from your account dashboard
</ul>

<h2>Step 3: Download and Configure the Tool</h2>
<p>Download the email_security_analyzer.py file from the attached code</br>
Open the file in a text editor</br>
Locate the CONFIG section near the top of the file</br>
Replace the placeholder values with your actual API keys:</br>
python
CONFIG = {
    "google_api_key": "YOUR_GOOGLE_API_KEY",
    "google_cx": "YOUR_GOOGLE_SEARCH_ENGINE_ID",
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY",
    "whoisxml_api_key": "YOUR_WHOISXML_API_KEY",
}

<h2>Step 4: Run the Tool</h2>
Open a command prompt or terminal
Navigate to the directory containing the script:
python email_security_analyzer.py


<h2>Using the Email Security Analyzer</h2>
The tool offers four main functions:
<ul>Header Analyzer
<li>Analyzes email headers for sender validation, SPF/DMARC checks
<li>Extracts domain information and checks against blocklists
<li>Identifies web and social media presence
<li>Domain Check
<li>Verifies domain registration information
<li>Shows registration dates, owner details, and name servers

<h2>Blocklist Check<h2>
<li>Checks if a domain or IP address is on security blocklists
<li>Reports security vendors that have flagged the entity
<li>Authentication Check
<li>Verifies SPF and DMARC records for a domain
<li>Determines if proper email authentication is in place

<h3>Example Usage<h3>
Analyzing Email Headers </br>
Select option 1 from the menu </br>
Paste the complete email headers when prompted</br>
Press Enter twice (blank line) to finish input</br>
Review the comprehensive analysis results</br>

<h2>Checking a Domain</h2>
Select option 2</br>
Enter the domain name (e.g., "example.com")</br>
Review the domain registration information</br>

<h2>Notes</h2>
Google's API has a limit of 100 free searches per day</br>
The WhoisXML API free tier has limited queries per month</br>
For optimal results, use complete email headers</br>
This Email Security Analyzer tool provides rapid security assessment of email communications, helping identify potential phishing attempts and validate sender authenticity through multiple security checks.
