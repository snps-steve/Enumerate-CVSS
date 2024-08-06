# Enumerate CVSS Script

## Overview

This repository contains a Python script designed to enumerate and analyze CVSS scores from Black Duck data. The script fetches information about vulnerable components in a specified project and version from the Black Duck Server's APIs and outputs relevant details.

The script provides options to set or confirm project details and API configuration from a `.env` file.

## Features

- Fetch Vulnerabilities: Retrieves vulnerable components from a specified Black Duck project and version using the Black Duck Server's APIs.
- Detailed Output: Provides detailed output of vulnerabilities, including component name, version, CVSS 2 and CVSS 3 scores.
- Export Results: Allows exporting the results to CSV or JSON format. The script will prompt the user at the end of execution to ask if exporting is necessary (Yes/No) and if so, what format (csv/json).

## Requirements

- Python 3.x
- Requests library
- Dotenv

You can install the required Python packages using pip or let the script install them for you:

```bash
pip install requests python-dotenv
```

## Installation
Clone this repository:

```bash
git clone https://github.com/snps-steve/Enumerate-CVSS/
```

Navigate to the project directory:

```bash
cd enumerate-cvss
```

### Usage
Set up your environment variables in a .env file or simply let the script prompt you for the required information. 

Run the script:

```bash
python enum_cvss.py
```

### Sample Output
When saved to CSV:

Component Name,Vulnerability ID,CVSS 2,CVSS 3<br>
Apache Portable Runtime,BDSA-2021-2583,5.0,7.5<br>
Apache Portable Runtime,BDSA-2023-0191,7.5,9.8<br>
Apache Portable Runtime,CVE-2021-35940,3.6,7.1<br>
Apache Portable Runtime,BDSA-2023-0190,7.5,9.8<br>
Apache Portable Runtime,CVE-2009-2699,5.0,7.5<br>
Apache Portable Runtime,BDSA-2023-0285,5.0,7.5<br>
Apache Portable Runtime,CVE-2017-12618,1.9,4.7<br>
<br><br>
The output can also be saved as a Json file.<br> 
<br>
### Configuration
During the first execution of the script, the user will be prompted for the BASEURL, API_TOKEN, project, and project version. These fields will then be stored in a .env file in the project folder. If a .env file is detected, the script will prompt you to either use the existing BASEURL, API_TOKEN, project, and project version as 'defaults' or you can enter different information.
<br><br>
Example .env file:
<br><br>
BASEURL=https://blackduck.synopsys.com<br>
API_TOKEN=[REDACTED]<br>
project_name=testVMDK<br>
version_name=1.0<br>
<br>
### License
This project is licensed under the MIT License.

### Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request.

### Contact
For any questions or issues, please contact Steve Smith (ssmith@blackduck.com).
