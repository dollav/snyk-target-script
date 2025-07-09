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
SNYKAPIVERSION = "2024-10-15"
APIKEY = "Token " + APIKEY

listofTargets = []
count = 0 


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


#https://api.snyk.io/rest/orgs/2f3d8682-4d92-454d-899f-8acb8eb5704e/projects?target_id=39940beb-94bf-4282-b0d0-efbe448e4f4f&version=2024-10-15
for target in listofTargets:

    projectsResponse = session.get("https://api.snyk.io/rest/orgs/{}/projects?target_id={}&version={}&limit=100".format(ORGID, target['id'],SNYKAPIVERSION), headers={'Authorization': APIKEY})
    projectResponseJSON = projectsResponse.json()
    hasGradle = False
    hasMaven = False

    for project in projectResponseJSON['data']:

        if project['attributes']['type'].lower() == "gradle":
            hasGradle = True
            print("has gradle")

        if project['attributes']['type'].lower() == "maven":
            hasMaven = True
            print("has maven")        

        if hasGradle & hasMaven:
            print(project)
            count = count + 1


print("Total targets with at least 1 maven and 1 gradle project: {}".format(count))