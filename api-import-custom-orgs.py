import json
import requests as reqs
from urllib3.util import Retry
import urllib3
from requests.adapters import HTTPAdapter
import os
import csv
import time



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

APIKEY =  os.getenv("APIKEY")
TEMPLATE_ORGID = os.getenv("TEMPLATE_ORGID")
APIKEY = "Token " + APIKEY
SNYK_GROUP_ID = os.getenv("SNYK_GROUP_ID")
GIT_OWNER = os.getenv("GIT_OWNER")
SNYK_API_ENDPOINT = os.getenv("SNYK_API_ENDPOINT")
scmSource = "github-cloud-app"


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


json_entries = {
  "targets": []
}


csvData = get_csv_rows_dict("import-data.csv")

for row in csvData:

    # swap to this when you have the app name
    # orgName = row['APPLICATION_NAME'] + "-" + row['mappid']

    orgName = row["MAP_ID"]
    checkOrgExistsURL = "https://{}/rest/groups/{}/orgs?version=2024-10-15&name={}".format(SNYK_API_ENDPOINT, SNYK_GROUP_ID, orgName)

    try:
        responseJSON = session.get(checkOrgExistsURL, headers={'Authorization': APIKEY})
        responseJSON.raise_for_status()
        responseJSON = responseJSON.json()
    except reqs.RequestException as ex:
        print("Some issue querying the Snyk API, exception: {}".format(ex))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
        continue
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
            urlResponseJSON = session.post("https:/{}/v1/org".format(SNYK_API_ENDPOINT), headers={'Authorization': APIKEY, "Content-Type": "application/json"}, data=json.dumps(data))
            urlResponseJSON.raise_for_status()

            #API endpoints take a moment to update, need to sleep to prevent duplicates
            #This could be improved by keeping a running list of duplicates, then skipping this step when its found in the list
            time.sleep(3)

        except reqs.exceptions.RequestException as ex:
            print(f"An error occurred: {ex}")
            continue
    else:
        print("Org already exists, continuing with import")

    #Get orgID for the current repo
    try:
        getOrgId = session.get("https://{}/rest/groups/{}/orgs?version=2024-10-15&name={}".format(SNYK_API_ENDPOINT, SNYK_GROUP_ID, orgName), headers={'Authorization': APIKEY})
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
        getIntegrationId = session.get("https://{}/v1/org/{}/integrations/{}".format(SNYK_API_ENDPOINT, importingOrgId, scmSource), headers={'Authorization': APIKEY})
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

#create our file
try:
    with open("import-data.json", 'w') as f:
        json.dump(json_entries, f, indent=2)
    print(f"\nSuccessfully wrote content to output")
except IOError as e:
    print(f"Error writing to file... {e}")