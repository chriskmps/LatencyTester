import ssl
import xmlrpc
import xmlrpc.client
import base64
import datetime

import requests
import urllib3
import json

import requests
import pandas as pd

import random
import string
import time
import sys

from urllib3.util import Retry
from requests.adapters import HTTPAdapter

### HTTP Adapter
DEFAULT_TIMEOUT = 5 # seconds

class TimeoutHTTPAdapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.timeout = DEFAULT_TIMEOUT
        if "timeout" in kwargs:
            self.timeout = kwargs["timeout"]
            del kwargs["timeout"]
        super().__init__(*args, **kwargs)

    def send(self, request, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.timeout
        return super().send(request, **kwargs)


### POST FUNCTIONS
def PostToUdl(udl_endpoint, username, unecrypted_password, json_data, http_session):
    # Load auth
    key = username + ":" + unecrypted_password
    authkey = base64.b64encode(key.encode('utf-8')).decode("ascii")
    #creds = "Basic Y2hyaXN0aWFuLmtlbXBpczo5OTkwMCFDSUshY2lrISEh"

    udl_headers = {'accept': 'application/json',
                  'content-type': 'application/json',
                  #'Authorization': creds}
                  'Authorization': 'Basic {auth}'.format(auth=authkey)}
    print("Invoking {url} endpoint".format(url=udl_endpoint))
    print("calling with {data}".format(data=json_data))

    try:
        response = http_session.post( udl_endpoint, 
                                      data = json.dumps(json_data),
                                      verify = False,
                                      headers = udl_headers)
        print("Completed data access at {url}".format(url=udl_endpoint))
    except requests.exceptions.RequestException as e:
        print(f"ERROR ON POST:  {e}")

    return response


def PostTestVector(udl_ep, udl_user, udl_pw, sync_pattern, time_stamp, http_session):
    try:
        state_vector_data = {
            "classificationMarking": "U",
            "msgType" : "LatencyTest",
            "source" : "MITRE",
            "msgBody" : {   "timeStamp" : time_stamp, 
                            "message" : "System latency test", 
                            "syncPattern" : sync_pattern
                        },
            "dataMode": "TEST"
        }

        print('Start executing UDL update for ' + udl_user)
        res = PostToUdl(udl_ep, udl_user, udl_pw, state_vector_data, http_session)
        print(res)
        print('Finished executing UDL update...')
        return res
    except xmlrpc.client.ProtocolError as err:
        print("A protocol error occurred")
        print("URL: %s" % err.url)
        print("HTTP/HTTPS headers: %s" % err.headers)
        print("Error code: %d" % err.errcode)
        print("Error message: %s" % err.errmsg)


### QUERY FUNCTIONS
def GetFromUdl(url_endpoint, http_session, creds):
    try:
        response = http_session.get(url_endpoint, headers={'Authorization':creds}, verify=False)

    except requests.exceptions.RequestException as e:
        print(f"ERROR ON GET:  {e}")

    if response.ok:
        print("Completed data retrieval at {url}".format(url=url_endpoint))

    return response


# Returns a single data frame with the matching sync pattern or empty data frame if non were found
def ScanDataFrameForOnSyncPattern(data_frame, sync_pattern):
    dfDecrementer = data_frame.shape[0] - 1    # Get amount of rows in the dataframe
    stopSearch = False
    returnValue = pd.DataFrame()

    while stopSearch == False:
        dataRow = data_frame.loc[dfDecrementer]

        if 'syncPattern' in dataRow['msgBody']:
            compString = dataRow['msgBody']['syncPattern']

            if(compString == sync_pattern):
                print(f"Test Message Found for: {sync_pattern}");
                returnValue = dataRow
                stopSearch = True;

        dfDecrementer -= 1

        if(dfDecrementer < 0):
            print(f"Did not find message for : {sync_pattern}")
            stopSearch = True
            break

    return returnValue

# Returns time difference between the local timep stmap and retrieved data frame
def GetServerCreationLatency(time_stamp, single_data_frame):
    serverTime = datetime.datetime.strptime(single_data_frame['createdAt'],"%Y-%m-%dT%H:%M:%S.%fZ")
    givenTime = datetime.datetime.strptime(time_stamp,"%Y-%m-%dT%H:%M:%S.%fZ")
    
    timeDifference = serverTime - givenTime

    print(f"Initial Start Time: {givenTime}")
    print(f"Server Created Time: {serverTime}")
    print(f"Total Time Difference: {timeDifference}")

    return timeDifference

def ConvertToMs(time):
    convert = str(round(time.total_seconds() * 1000)) + 'ms'
    return convert

if __name__=="__main__":
    # Variables
    timeToPost = 0
    timeToGet = 0
    timeDiffOnServerCreate = 0
    credsData = 0
    user = 0
    password = 0
    creds = 0
    serviceEndpointTest = 0
    retries = 0
    retryTimeoutAdapter = 0
    httpSession = 0
    syncPattern = 0
    timeStamp = 0
    postResult = 0
    getResult = 0
    elsetsDataFrame = 0
    singleDataFrame = 0

    # Load All credentials
    with open('creds.json') as creds:
        credsData = json.load(creds)

    user = credsData['user']
    password = credsData['password']
    creds = credsData['creds']
    serviceEndpointTest = credsData['service_endpoint_test']

    # Load HTTP services
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    retryTimeoutAdapter = TimeoutHTTPAdapter(max_retries=retries)
    httpSession = requests.Session()
    httpSession.mount("https://",retryTimeoutAdapter)
    httpSession.mount("http://",retryTimeoutAdapter)

    # Generate sync pattern for retrieval
    syncPattern = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    timeStamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
    timeStamp = timeStamp + 'Z'

    # POST TO SERVER
    postResult = PostTestVector(serviceEndpointTest, user, password, syncPattern, timeStamp, httpSession)
    if(hasattr(postResult,'ok') and postResult.ok):
        timeToPost = ConvertToMs(postResult.elapsed)

    # QUERY FROM SERVER
    getResult = GetFromUdl(serviceEndpointTest, httpSession, creds)
    if(hasattr(getResult,'ok') and getResult.ok):
        timeToGet = ConvertToMs(getResult.elapsed)
        elsetsDataFrame = pd.DataFrame(getResult.json())
        singleDataFrame = ScanDataFrameForOnSyncPattern(elsetsDataFrame, syncPattern)

    # PROCESS RESULTS
    if(singleDataFrame.empty == True):
        print("Find Frame on Sync Pattern Failure")
    else:
        timeDiffOnServerCreate = ConvertToMs(GetServerCreationLatency(timeStamp, singleDataFrame))
       
    print(f"POST TIME: {timeToPost}")
    print(f"GET TIME:  {timeToGet}")
    print(f"TIME DIFF: {timeDiffOnServerCreate}")
    outString = f"Run_Date: {timeStamp}\nSync_Pattern: {syncPattern}\nPost_Latency: {timeToPost}\nGet_Latency: {timeToGet}\nServer_Response_Latency: {timeDiffOnServerCreate}\n\n" 

    # Write to log
    f = open("logger.txt", "a")
    f.write(outString);
    f.close();
