import requests as reqs
from urllib3.util import Retry
import urllib3
from requests.adapters import HTTPAdapter
import os
import csv

#Retry logic
retry_strategy = Retry(
    total=5,  # Maximum number of retries
    status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
    backoff_factor=5
    )
adapter = HTTPAdapter(max_retries=retry_strategy)
session = reqs.Session()
session.mount('https://', adapter)
urllib3.add_stderr_logger()

APIKEY =  os.getenv("APIKEY")
GROUPID = os.getenv("GROUPID")
SNYKAPIVERSION = "2024-10-15"
APIKEY = "Token " + APIKEY


class snykIssue:
  def __init__(self, projectName, projectID, orgID, severity, title, filename, linenumber):
    self.projectName = projectName
    self.projectID = projectID
    self.orgID = orgID
    self.severity = severity
    self.title = title
    self.filename = filename
    self.linenumber = linenumber

allOrganizations = []
allOrgIssues = []
allIssuesWithMetadata = []
projectIDtoProjectName = {}
orgIDtoNameMapping = {}

#Grab a list of all organizations related to the given group
try:
    organizationURL = "https://api.snyk.io/rest/groups/{}/orgs?version={}&limit=100".format(GROUPID, SNYKAPIVERSION)
    while True:
        organizationResponse = session.get(organizationURL, headers={'Authorization': APIKEY})
        organizationResponse.raise_for_status()
        organizationResponse = organizationResponse.json()
        allOrganizations.extend(organizationResponse['data'])
        nextPage = organizationResponse['links'].get('next')
        if not nextPage:
            break
        organizationURL = "https://api.snyk.io{}".format(nextPage)
except reqs.RequestException as ex:
    print("Some issue querying the Snyk API {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


# Map IDs to names so that later we can store the names as values in place of ID

for org in allOrganizations:
    orgIDtoNameMapping[org['id']] = org['attributes']['name']

#For each organization in the list

for org in allOrganizations:
    issueURL = "https://api.snyk.io/rest/orgs/{}/issues?version={}&type=code".format(org.get('id'), SNYKAPIVERSION)
    while True:
        try:
            issueResponse = session.get(issueURL, headers={'Authorization': APIKEY})
            issueResponse.raise_for_status()
            issueResponse = issueResponse.json()
            nextPage = organizationResponse['links'].get('next')
            allOrgIssues.extend(issueResponse['data'])

            if not nextPage:
                break
            issueURL = "https://api.snyk.io{}".format(nextPage)
        except reqs.exceptions.RequestException as ex:
            print("Some issue querying the Snyk API {}".format(ex))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            break

    allOrgIssues = sorted(allOrgIssues, key=lambda x: x['relationships']['scan_item']['data']['id'])

    for issue in allOrgIssues:
        issueID = issue['attributes']['problems'][0]['id']
        orgID = issue['relationships']['organization']['data']['id']

        if issue['relationships']['scan_item']['data']['type'] == 'project':
            projectID = issue['relationships']['scan_item']['data']['id']
        else:
            print("Item source is not a project, is instead {}. Skipping...".format(issue['relationships']['scan_item']['data']['type']))
            continue
        
        #The response comes back like this for location: {'endLine': 25, 'endColumn': 33, 'startLine': 25, 'startColumn': 26} - I am using the start line but the script can be modified to use all or any of these.
        try:
            codeIssueURL = "https://api.snyk.io/rest/orgs/{}/issues/detail/code/{}?project_id={}&version=2024-04-06%7Eexperimental".format(orgID, issueID, projectID)
            codeIssueresponse = session.get(codeIssueURL, headers={'Authorization': APIKEY})
            codeIssueresponse.raise_for_status()
            codeIssueresponse = codeIssueresponse.json()
        except reqs.exceptions.RequestException as ex:
            print("Some issue querying the Snyk API {}".format(ex))
            print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
            continue

        if projectIDtoProjectName.get(projectID) is not None:
            projectName = projectIDtoProjectName.get(projectID)
        else:
        #Project name is not returned by any of the APIs we are already using only ID
            try:
                projectURL = "https://api.snyk.io/rest/orgs/{}/projects/{}?version=2024-10-15".format(orgID, projectID)
                projectResponse = session.get(projectURL, headers={'Authorization': APIKEY})
                projectResponse = projectResponse.json()
                projectName = projectResponse['data']['attributes']['name']
                projectIDtoProjectName[projectID] = projectResponse['data']['attributes']['name']
            except reqs.exceptions.RequestException as exß:
                print("Some issue querying the Snyk API {}".format(ex))
                print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")
                continue
            
        allIssuesWithMetadata.append(snykIssue(projectName, projectID, orgIDtoNameMapping.get(orgID), issue['attributes']['effective_severity_level'], codeIssueresponse['data']['attributes']['title'], codeIssueresponse['data']['attributes']['primaryFilePath'], codeIssueresponse['data']['attributes']['primaryRegion']['startLine']))




csvFields = ['Project Name', 'Project ID', 'Org ID', 'Severity', 'Title', 'File Name', 'Line']

with open('VulnData.csv', 'w') as f:
    csv_writer = csv.writer(f)
    csv_writer.writerow(csvFields)
    for projectIssue in allIssuesWithMetadata:
        constructRow = [projectIssue.projectName, projectIssue.projectID, projectIssue.orgID, projectIssue.severity, projectIssue.title, projectIssue.filename, projectIssue.linenumber]
        csv_writer.writerow(constructRow)