#!/usr/bin/env python3

import os
import sys
import json
import csv
import requests
import logging
from datetime import datetime
from dotenv import load_dotenv
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to prompt user with a default value
def prompt_with_default(prompt, default):
    user_input = input(f"{prompt} (default: {default}): ").strip()
    return user_input if user_input else default

# Load environment variables from .env file
def load_env_variables():
    if os.path.exists('.env'):
        load_dotenv()
        logging.info("Detected .env file.")
    else:
        logging.info(".env file not detected. You will be prompted to enter environment variables.")

    global BASEURL, API_TOKEN, project_name, version_name

    BASEURL = os.getenv('BASEURL')
    API_TOKEN = os.getenv('API_TOKEN')
    project_name = os.getenv("project_name")
    version_name = os.getenv("version_name")

    BASEURL = prompt_with_default("Enter BASEURL", BASEURL)
    API_TOKEN = prompt_with_default("Enter API_TOKEN", API_TOKEN)
    project_name = prompt_with_default("Enter your Project Name", project_name)
    version_name = prompt_with_default("Enter your Version Name", version_name)

    with open('.env', 'w') as f:
        f.write(f"BASEURL={BASEURL}\n")
        f.write(f"API_TOKEN={API_TOKEN}\n")
        f.write(f"project_name={project_name}\n")
        f.write(f"version_name={version_name}\n")

load_env_variables()

AUTHURL = f"{BASEURL}/api/tokens/authenticate"
http_method = "GET"
payload = {}
output = {
    'logs': [],
    'components': []
}

def log(entry):
    '''
    Append new log entries
    '''
    output['logs'].append(entry)

    with open("logfile.json", "w") as outfile:
        json.dump(output, outfile, indent=4)

def http_error_check(url, headers, code, response):
    '''
    Function to check the HTTP status code.
    '''
    if code == 200:
        return

    if code > 399:
        logging.error(f"Unable to pull info from endpoint. URL: {url}, HTTP error: {code}")
        log(f"{datetime.now().strftime('%Y-%m-%d %H:%M')} URL: {url} HEADERS: {headers} HTTP error: {code}")
        log(response.text)
        sys.exit()
    else:
        raise Exception("Error while getting data.", code)

def get_auth():
    '''
    Function to authenticate to the BD API and grab the bearer token and csrf token.
    '''
    url = AUTHURL
    headers = {
        'Accept': 'application/vnd.blackducksoftware.user-4+json',
        'Authorization': 'token ' + API_TOKEN
    }

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    try:
        response = requests_retry_session().post(url, headers=headers, data=payload, verify=False, timeout=15)
        code = response.status_code
        http_error_check(url, headers, code, response)

        if code == 200:
            global bearerToken, csrfToken
            bearerToken = response.json()['bearerToken']
            csrfToken = response.headers['X-CSRF-TOKEN']
    except requests.exceptions.RequestException as e:
        logging.error(f"Authentication failed: {e}")
        sys.exit()

def get_url(http_method, url, headers, payload):
    '''
    Function to enumerate data from a URL or API endpoint.
    '''
    try:
        response = requests_retry_session().request(http_method, url, headers=headers, data=payload, verify=False, timeout=15)
        code = response.status_code
        http_error_check(url, headers, code, response)

        if code == 200:
            return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Request failed: {e}")
        sys.exit()

def get_project_id_by_name(project_name):
    '''Function to get the project ID by project name.'''
    url = f"{BASEURL}/api/projects?q=name:{project_name}"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.project-detail-5+json"
    }
    response_json = get_url("GET", url, headers, payload)
    if response_json and 'items' in response_json and len(response_json['items']) > 0:
        return response_json['items'][0]['_meta']['href'].split('/')[-1]
    else:
        logging.error(f"Project with name '{project_name}' not found.")
        sys.exit()

def get_version_id_by_name(project_id, version_name):
    '''Function to get the version ID by version name.'''
    url = f"{BASEURL}/api/projects/{project_id}/versions?q=versionName:{version_name}"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.project-detail-5+json"
    }
    response_json = get_url("GET", url, headers, payload)
    if response_json and 'items' in response_json and len(response_json['items']) > 0:
        return response_json['items'][0]['_meta']['href'].split('/')[-1]
    else:
        logging.error(f"Version with name '{version_name}' not found in project ID '{project_id}'.")
        sys.exit()

def get_vulnerable_components(project_id, version_id):
    '''Function to get the vulnerable components and their vulnerabilities.'''
    url = f"{BASEURL}/api/projects/{project_id}/versions/{version_id}/vulnerable-bom-components"
    headers = {
        "Authorization": "Bearer " + bearerToken,
        "Accept": "application/vnd.blackducksoftware.bill-of-materials-6+json"
    }
    response_json = get_url("GET", url, headers, payload)
    return response_json

def get_components():
    '''Function to get the components and their vulnerabilities.'''
    logging.info("Getting components for the project and version...")
    project_id = get_project_id_by_name(project_name)
    version_id = get_version_id_by_name(project_id, version_name)
    vulnerable_components = get_vulnerable_components(project_id, version_id)
    for component in vulnerable_components.get('items', []):
        component_name = component.get('componentName')
        logging.info(f"Component name: {component_name}")
        get_vulnerabilities(component_name)

def get_vulnerabilities(component_name):
    '''
    Function to enumerate vulnerable components from a list of components.
    '''
    url = f'{BASEURL}/api/search/vulnerabilities?limit=100&offset=0&q={component_name}'
    headers = {
        'Accept': 'application/vnd.blackducksoftware.internal-1+json',
        'Authorization': 'bearer ' + bearerToken,
        'X-CSRF-TOKEN': csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    if not results['items']:
        logging.info(f"No vulnerabilities found for component: {component_name}")
        vuln_id = "00000"
        cvss2 = "0"
        cvss3 = "0"
        log(f"{component_name}, {vuln_id}, {cvss2}, {cvss3}")
        return

    for vulns in results['items']:
        try:
            vuln_id = vulns['vulnerabilityId']
            logging.info(f"Vulnerability ID: {vuln_id}")
            get_cvss(component_name, vuln_id)
        except KeyError:
            continue

def get_cvss(component_name, vuln_id):
    '''
    Function to enumerate CVSS 2 and CVSS 3 scores using vuln_id.
    '''
    url = f'{BASEURL}/api/vulnerabilities/{vuln_id}'
    headers = {
        'Accept': 'application/vnd.blackducksoftware.vulnerability-4+json',
        'Authorization': 'bearer ' + bearerToken,
        'X-CSRF-TOKEN': csrfToken
    }
    results = get_url(http_method, url, headers, payload)

    cvss2 = results['cvss2']['baseScore']
    cvss3 = results['cvss3']['baseScore']
    
    logging.info(f"CVSS 2 Base Score: {cvss2}")
    logging.info(f"CVSS 3 Base Score: {cvss3}")

    log(f"{component_name}, {vuln_id}, {cvss2}, {cvss3}")

def export_results():
    '''
    Function to export results to CSV or JSON based on user selection.
    '''
    save_choice = input("Do you want to save the results? (Yes/no, default is Yes): ").strip().lower()
    if save_choice not in ('', 'y', 'yes'):
        logging.info("Results not saved.")
        return

    choice = input("Do you want to export the results to CSV or JSON? (default is JSON): ").strip().lower()
    if choice in ('', 'json'):
        with open('results.json', 'w') as outfile:
            json.dump(output, outfile, indent=4)
        logging.info("Results exported to results.json")
    elif choice == 'csv':
        with open('results.csv', 'w', newline='') as csvfile:
            fieldnames = ['Component Name', 'Vulnerability ID', 'CVSS 2', 'CVSS 3']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()
            for log_entry in output['logs']:
                component_name, vuln_id, cvss2, cvss3 = log_entry.split(', ')
                writer.writerow({
                    'Component Name': component_name,
                    'Vulnerability ID': vuln_id,
                    'CVSS 2': cvss2,
                    'CVSS 3': cvss3
                })
        logging.info("Results exported to results.csv")
    else:
        logging.info("Invalid input. Results not exported.")

def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = requests.packages.urllib3.util.retry.Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = requests.adapters.HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def main():
    '''
    Main function
    '''
    logging.info("Starting script...")
    get_auth()
    get_components()
    export_results()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Control-C detected, exiting.")
        sys.exit()
