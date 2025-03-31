import json
import time
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
    backoff_factor=5,
    allowed_methods= ["GET","POST"]
    )
adapter = HTTPAdapter(max_retries=retry_strategy,)
session = reqs.Session()
session.mount('https://', adapter)
urllib3.add_stderr_logger()

APIKEY =  os.getenv("APIKEY")
ORGID = os.getenv("ORGID")
SNYKAPIVERSION = "2024-10-15"
APIKEY = "Token " + APIKEY
SNYK_GROUP_ID = os.getenv("SNYK_GROUP_ID")


try:
    with open("config.json", 'r') as f:
        config_data = json.load(f)
    post_data_url = "https://api.snyk.io/rest/groups/{}/export?version=2024-10-15~experimental".format(SNYK_GROUP_ID)
    post_data_resp = session.post(post_data_url, json=config_data, headers={'Authorization': APIKEY})
    post_data_resp.raise_for_status()
    post_data_resp = post_data_resp.json()
    job_id = post_data_resp['data']['links']['self']
    print("succesful call, looping while we wait for job ID ({}) to return as complete".format(job_id))

except reqs.RequestException as ex:
    print("Some issue querying the Snyk API {}".format(ex))
    print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")



while True:

    try:
        check_job_status_url = "https://api.snyk.io/rest{}?version=2024-10-15~experimental".format(job_id)
        status_resp = session.get(check_job_status_url , headers={'Authorization': APIKEY})
        status_resp.raise_for_status()
        status_resp_json = status_resp.json()
        print("status {}".format(status_resp_json['data']['attributes']['status']))

        if status_resp_json['data']['attributes']['status'] != "FINISHED":
            print("Job status is {}, waiting 10 seconds then trying again..".format(status_resp_json['data']['attributes']['status']))
            time.sleep(10)
        else:
            for result in status_resp_json['data']['attributes']['results']:

                csv_response = session.get(status_resp_json['data']['attributes']['results'][0]['url'], headers={'Authorization': APIKEY})
                csv_response.raise_for_status()

                count = 0

                filename = "CSV-" + str(count) + ".csv"
                with open(filename, 'wb') as file: 
                    file.write(csv_response.content)
                count = count + 1
            break

    except:
        print("Some issue querying the Snyk API {}".format(ex))
        print("If this error looks abnormal please check https://status.snyk.io/ for any incidents")


