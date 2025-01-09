import requests as reqs
from urllib3.util import Retry
import urllib3
from requests.adapters import HTTPAdapter
import os
import csv
import re

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
ORGID = os.getenv("ORGID")
SNYKAPIVERSION = "2024-10-15"
APIKEY = "Token " + APIKEY


class targetObject:
  def __init__(self, targetName, targetID, projectCount, criticals, highs, mediums, lows, source, url):
    self.targetName = targetName
    self.targetID = targetID
    self.projectCount = projectCount
    self.criticals = criticals
    self.highs = highs
    self.mediums = mediums
    self.lows = lows
    self.targetSource = source
    self.url = url

# We want to pull a full list of targets from the Snyk UI. This is specifically filtering on SCM sources: =bitbucket-server%2Cgithub-enterprise%2Cgithub%2Cgithub-cloud-app
listofTargets = []
try:
    allTargetsURL = "https://api.snyk.io/rest/orgs/{}/targets?version={}&limit=100&source_types=bitbucket-server%2Cgithub-enterprise%2Cgithub%2Cgithub-cloud-app".format(ORGID, SNYKAPIVERSION)
    while True:
        targetResponse = session.get(allTargetsURL, headers={'Authorization': APIKEY})
        targetResponse.raise_for_status()
        targetResponseJSON = targetResponse.json()
        listofTargets.extend(targetResponseJSON['data'])
        nextPageTargetURL = targetResponseJSON['links'].get('next')
        if not nextPageTargetURL:
            break
        allTargetsURL = "https://api.snyk.io{}".format(nextPageTargetURL)
except reqs.RequestException as ex:
    print("Some issue querying the Snyk API {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")

targetObjects = []


# We sanitize the remote URL to be HTTP as there is sanitzation that happens in the Snyk Backend which requires this - This can be treated as a stable interface and is unlikely to change in the future
# If that remote URL exists as an object (CLI scan happend and a Snyk monitor ran with --remote-repo-url=<URL>), then we want to use that information to create the object instead of the SCM based project
try:
    for target in listofTargets:

        sanitizedURL = re.sub(r'https://', 'http%3A%2F%2F', target['attributes']['url'])
        sanitizedURL = re.sub(r'/', '%2F', sanitizedURL)
        validateTargetURL = "https://api.snyk.io/rest/orgs/{}/targets?version={}&url={}&source_types=cli".format(ORGID, SNYKAPIVERSION, sanitizedURL)
        validationResponse = session.get(validateTargetURL, headers={'Authorization': APIKEY})
        validationResponse.raise_for_status()
        validationResponse = validationResponse.json()

        if len(validationResponse.get("data")) > 0:
            targetObjects.append(targetObject(validationResponse['data'][0]['attributes']['display_name'], validationResponse['data'][0]['id'], 0, 0, 0, 0, 0, validationResponse['data'][0]['relationships']['integration']['data']['attributes']['integration_type'], validationResponse['data'][0]['attributes']['url']))
        else:
            targetObjects.append(targetObject(target['attributes']['display_name'], target['id'], 0, 0, 0, 0, 0, target['relationships']['integration']['data']['attributes']['integration_type'] ,target['attributes']['url']))

except reqs.RequestException as ex:
    print("Some issue querying the Snyk API {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")



count = len(targetObjects)

# Take our finalized list and grab vulnerability information for the relevant target and underlying projects. This gets saved into a CSV.
try:
    for target in targetObjects:
        while True:
            print("Curently remaining: {}".format(count))
            count = count - 1 
            targetDataURL = "https://api.snyk.io/rest/orgs/{}/projects?target_id={}&version={}&limit=100".format(ORGID, target.targetID, SNYKAPIVERSION)
            projectData = session.get(targetDataURL, headers={'Authorization': APIKEY})
            projectData.raise_for_status()
            projectDataJSON = projectData.json()
            nextPageProjectURL = targetResponseJSON['links'].get('next')
            #count of projects within each targetID
            target.projectCount = target.projectCount + len(projectDataJSON['data'])
            # Reach out for vulns
            for project in projectDataJSON['data']:
                projectVulnInfo = "https://api.snyk.io/v1/org/{}/project/{}".format(ORGID, project['id'])
                vulnInfo = session.get(projectVulnInfo, headers={'Authorization': APIKEY})
                vulnInfoJSON = vulnInfo.json()
                if vulnInfoJSON['type'] == "cloudformationconfig" or vulnInfoJSON['type'] == "k8sconfig" or vulnInfoJSON['type'] == "dockerfile":
                    target.projectCount = target.projectCount - 1
                    continue
            
                #If you only want to store data on Gradle projects, you can do something like 
                #if vulnInfoJSON['type] != 'gradle': 
                # targetObjects.remove(target)
                #continue

                print(vulnInfoJSON['type'])
                target.criticals = vulnInfoJSON['issueCountsBySeverity']['critical'] + target.criticals
                target.highs = vulnInfoJSON['issueCountsBySeverity']['high'] + target.highs
                target.mediums = vulnInfoJSON['issueCountsBySeverity']['medium'] + target.mediums
                target.lows = vulnInfoJSON['issueCountsBySeverity']['low'] + target.lows
            if not nextPageProjectURL:
                break
            targetDataURL = "https://api.snyk.io{}".format(nextPageProjectURL)

        print("target name: {} | criticals {} | highs {} | mediums {} | lows {} | Source {} | URL {} ".format(target.targetName, target.criticals, target.highs, target.mediums, target.lows, target.targetSource, target.url))

except reqs.RequestException as ex:
    print("Some issue querying the Snyk API, exception: {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


csvFields = ['Target Name', 'Target ID', 'Project Count', 'Total Criticals', 'Total Highs', 'Total Mediums', 'Total lows', 'Target Source', 'Target URL']

with open('VulnData.csv', 'w') as f:
    csv_writer = csv.writer(f)
    csv_writer.writerow(csvFields)
    for target in targetObjects:
        constructRow = [target.targetName, target.targetID, target.projectCount, target.criticals, target.highs, target.mediums, target.lows, target.targetSource, target.url]
        csv_writer.writerow(constructRow)
