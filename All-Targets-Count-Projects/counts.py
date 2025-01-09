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
ORGID = os.getenv("ORGID")
SNYKAPIVERSION = "2024-04-11"
APIKEY = "Token " + APIKEY


class targetObject:
  def __init__(self, targetName, targetID, projectCount, criticals, highs, mediums, lows):
    self.targetName = targetName
    self.targetID = targetID
    self.projectCount = projectCount
    self.criticals = criticals
    self.highs = highs
    self.mediums = mediums
    self.lows = lows  


listofTargets = []
try:
    allTargetsURL = "https://api.snyk.io/rest/orgs/{}/targets?version={}&limit=100".format(ORGID, SNYKAPIVERSION)
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
for target in listofTargets:
    targetObjects.append(targetObject(target['attributes']['display_name'], target['id'], 0, 0, 0, 0, 0))


try:
    for target in targetObjects:
        while True:
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
                target.criticals = vulnInfoJSON['issueCountsBySeverity']['critical'] + target.criticals
                target.highs = vulnInfoJSON['issueCountsBySeverity']['high'] + target.highs
                target.mediums = vulnInfoJSON['issueCountsBySeverity']['medium'] + target.mediums
                target.lows = vulnInfoJSON['issueCountsBySeverity']['low'] + target.lows
            if not nextPageProjectURL:
                break
            targetDataURL = "https://api.snyk.io{}".format(nextPageProjectURL)

        print("target name: {} | criticals {} | highs {} | mediums {} | lows {}".format(target.targetName, target.criticals, target.highs, target.mediums, target.lows))
except reqs.RequestException as ex:
    print("Some issue querying the Snyk API, exception: {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


csvFields = ['Target Name', 'Target ID', 'Project Count', 'Total Criticals', 'Total Highs', 'Total Mediums', 'Total lows']

with open('VulnData.csv', 'w') as f:
    csv_writer = csv.writer(f)
    csv_writer.writerow(csvFields)
    for target in targetObjects:
        constructRow = [target.targetName, target.targetID, target.projectCount, target.criticals, target.highs, target.mediums, target.lows]
        csv_writer.writerow(constructRow)