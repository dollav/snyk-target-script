import argparse
import json
import requests as reqs
from urllib3.util import Retry
import urllib3
from requests.adapters import HTTPAdapter
import os
import csv
import time

APIKEY = None
TEMPLATE_ORGID = None
SNYK_GROUP_ID = None
GIT_OWNER = None
SNYK_API_ENDPOINT = None
SCM_SOURCE = None
#Retry logic
retry_strategy = Retry(
    total=5,  # Maximum number of retries
    status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
    backoff_factor=5,
    allowed_methods= ["GET","POST"]
    )
adapter = HTTPAdapter(max_retries=retry_strategy,)
session = reqs.Session()
session.mount('https://', adapter)
#urllib3.add_stderr_logger()


def get_csv_rows_dict(filepath):
    """
    Opens a CSV file with a header and returns a list of dictionaries,
    where each dictionary represents a row with header names as keys.
    """
    rows = []
    try:
        with open(filepath, mode='r', newline='', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            for row in reader:
                rows.append(row)
        return rows
    except FileNotFoundError:
        print(f"Error: The file '{filepath}' was not found.")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def check_org_exists(orgName):

    checkOrgExistsURL = "https://{}/rest/groups/{}/orgs?version=2024-10-15&name={}".format(SNYK_API_ENDPOINT, SNYK_GROUP_ID, orgName)
    try:
        responseJSON = session.get(checkOrgExistsURL, headers={'Authorization': APIKEY})
        responseJSON.raise_for_status()
        responseJSON = responseJSON.json()
    except reqs.RequestException as ex:
        print("Some issue querying the Snyk API, exception: {}".format(ex))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

    print(responseJSON)

    #If the response data is empty, then create the organization by copying from our template ID
    if not responseJSON['data']:
        print("Org {} not found in group {}, creating new org...".format(orgName, SNYK_GROUP_ID))

        data = {
            "name": orgName,
            "groupId": SNYK_GROUP_ID,
            "sourceOrgId": TEMPLATE_ORGID
        }

        try:
            urlResponseJSON = session.post("https://{}/v1/org".format(SNYK_API_ENDPOINT), headers={'Authorization': APIKEY, "Content-Type": "application/json"}, data=json.dumps(data))
            urlResponseJSON.raise_for_status()

            #API endpoints take a moment to update, need to sleep to prevent duplicates
            #This could be improved by keeping a running list of duplicates, then skipping this step when its found in the list
            time.sleep(3)
        except reqs.exceptions.RequestException as ex:
            print(f"An error occurred: {ex}")
            
    else:
        print("Org already exists, continuing with import")

def write_to_json_output(json_output):
    try:
        with open("import-data.json", 'w') as f:
            json.dump(json_entries, f, indent=2)
        print(f"\nSuccessfully wrote content to output")
    except IOError as e:
        print(f"Error writing to file... {e}")


def main():
    """
    Parses command-line arguments and displays the configured values.
    """
    parser = argparse.ArgumentParser(
        description="A Python program that allows for custom imports from the api import tool"
    )

    global APIKEY, TEMPLATE_ORGID, SNYK_GROUP_ID, GIT_OWNER, SNYK_API_ENDPOINT, SCM_SOURCE

    # Add required command-line arguments
    parser.add_argument(
        "--snyk-api-key",
        type=str,
        required=True,
        help="Your Snyk API Key (e.g., 'your_snyk_api_key_here')."
    )
    parser.add_argument(
        "--template-org-id",
        type=str,
        required=True,
        help="The template organization ID for Snyk (e.g., 'abcdef12-3456-7890-abcd-ef1234567890')."
    )
    parser.add_argument(
        "--snyk-group-id",
        type=str,
        required=True,
        help="The Snyk Group ID (e.g., '12345678-abcd-efgh-ijkl-mnopqrstuvwx')."
    )
    parser.add_argument(
        "--git-owner",
        type=str,
        required=True,
        help="The Git owner (e.g., 'your_github_username_or_org')."
    )
    parser.add_argument(
        "--snyk-api-endpoint",
        type=str,
        required=True,
        help="The Snyk API endpoint (e.g., 'https://api.snyk.io/v1')."
    )
    parser.add_argument(
        "--scm-source",
        type=str,
        required=True,
        help="SCM Source that you are importing repositories from. "
    )
    # Parse the arguments provided by the user
    args = parser.parse_args()

    # Access the arguments and process them
    APIKEY = "Token " + args.snyk_api_key
    TEMPLATE_ORGID = args.template_org_id
    SNYK_GROUP_ID = args.snyk_group_id
    GIT_OWNER = args.git_owner
    SNYK_API_ENDPOINT = args.snyk_api_endpoint
    SCM_SOURCE = args.scm_source 

    print(f"Configured Values:")
    print(f"APIKEY: {APIKEY}")
    print(f"TEMPLATE_ORGID: {TEMPLATE_ORGID}")
    print(f"SNYK_GROUP_ID: {SNYK_GROUP_ID}")
    print(f"GIT_OWNER: {GIT_OWNER}")
    print(f"SNYK_API_ENDPOINT: {SNYK_API_ENDPOINT}")
    print(f"scmSource: {SCM_SOURCE}")

if __name__ == "__main__":
    main()



json_entries = {
  "targets": []
}

csvData = get_csv_rows_dict("import-data.csv")

for row in csvData:

    # swap to this when you have the app name
    # orgName = row['APPLICATION_NAME'] + "-" + row['mappid']
    check_org_exists(row["MAP_ID"])
 
    #Get orgID for the current repo
    try:
        getOrgId = session.get("https://{}/rest/groups/{}/orgs?version=2024-10-15&name={}".format(SNYK_API_ENDPOINT, SNYK_GROUP_ID, row["MAP_ID"]), headers={'Authorization': APIKEY})
        getOrgId.raise_for_status()
        getOrgId = getOrgId.json()
            
        if getOrgId['data']:
            importingOrgId = getOrgId['data'][0]['id']
            print(importingOrgId)
    except reqs.exceptions.RequestException as ex:
        print(f"An error occurred: {ex}")
        continue    
        

    #find integration ID for the current repo
    try:
        getIntegrationId = session.get("https://{}/v1/org/{}/integrations/{}".format(SNYK_API_ENDPOINT, importingOrgId, SCM_SOURCE), headers={'Authorization': APIKEY})
        getIntegrationId.raise_for_status()
        getIntegrationId = getIntegrationId.json()
            
        if getIntegrationId['id']:
            importingOrgIntegrationId = getIntegrationId['id']

    except reqs.exceptions.RequestException as ex:
        print(f"An error occurred: {ex}")
        continue    

    #write entry to variable
    currentEntry = {
        "orgId": importingOrgId,
        "integrationId": importingOrgIntegrationId,
        "target": {
            "name": row['Repo'],
            "owner": GIT_OWNER,
            "branch": ""
        }
    }

    json_entries["targets"].append(currentEntry)

write_to_json_output(json_entries)