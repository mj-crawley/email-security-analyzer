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
<h3>The tool requires the following API keys:</h3>
<ul><li>Google Custom Search API</li>
<li>VirusTotal API</li>
<li>AbuseIPDB API</li>
<li>WhoisXML API</li>
</ul>

<h2>Step 3: Download and Configure the Tool</h2>
Download the email_security_analyzer.py file from the attached code
Open the file in a text editor
Locate the CONFIG section near the top of the file
Replace the placeholder values with your actual API keys:</br></br>
CONFIG = {</br>
    "google_api_key": "YOUR_GOOGLE_API_KEY",</br>
    "google_cx": "YOUR_GOOGLE_SEARCH_ENGINE_ID",</br>
    "virustotal_api_key": "YOUR_VIRUSTOTAL_API_KEY",</br>
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY",</br>
    "whoisxml_api_key": "YOUR_WHOISXML_API_KEY",</br>
}

<h2>Step 4: Run the Tool</h2>
Open a command prompt or terminal
Navigate to the directory containing the script:
python email_security_analyzer.py


<h2>Using the Email Security Analyzer</h2> The tool offers four main functions

<h3>Header Analyzer:</h3>
<ul><li>Analyzes email headers for sender validation, SPF/DMARC checks</li>
<li>Extracts domain information and checks against blocklists</li>
<li>Identifies web and social media presence</li>
<li>Domain Check</li>
<li>Verifies domain registration information</li>
<li>Shows registration dates, owner details, and name servers</li>
</ul>

<h3>Blocklist Check</h3>
<ul><li>Checks if a domain or IP address is on security blocklists</li>
<li>Reports security vendors that have flagged the entity</li>                                      
<li>Authentication Check</li>
<li>Verifies SPF and DMARC records for a domain</li>
<li>Determines if proper email authentication is in place</li>
</ul>
</br>

<p>
<b>Example Usage</b></br>
Analyzing Email Headers:</br>
Select option 1 from the menu </br>
Paste the complete email headers when prompted</br>
Press Enter twice (blank line) to finish input</br>
Review the comprehensive analysis results</br>
</p>

<h3>Checking a Domain</h3>
<ul><li>Select option 2</br>
<li>Enter the domain name (e.g., "google.com")</li>
<li>Review the domain registration information</li>
</ul>

<h2>Notes</h2>
Google's API has a limit of 100 free searches per day</br>
The WhoisXML API free tier has limited queries per month</br>
For best results, use complete email headers</br>
