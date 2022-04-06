#!/usr/bin/env python
import sys
import csv
from argparse import ArgumentParser
import requests
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-f", "--filter", dest="filter", help="Filters the list for process with Java 9+ and Tomcat 9+", action='store_true')

parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
filter = args.filter
verifySSL = not args.insecure

cve = 'CVE-2022-22965'

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

class DynatraceApi:
    def __init__(self, tenant, apiToken, verifySSL = True):
        self.tenant = tenant
        self.apiToken = apiToken
        self.verifySSL = verifySSL

    def queryApi(self, endpoint):
            """
            Calls the given endpoint on the Dynatrace API. 
            param: string endpoint: API endpoint to be called
            return: response as json
            """
            authHeader = {'Authorization' : 'Api-Token '+ self.apiToken}
            url = self.tenant + endpoint
            response = requests.get(url, headers=authHeader, verify=self.verifySSL)
            logging.info('API Call Status: %s Request: %s', response.status_code, url);
            logging.debug('Response: %s', response.content)
            if response.reason != 'OK':
                logging.error('Request %s failed', url)
                logging.error('Status Code: %s (%s), Response: %s', response.status_code, response.reason, response.content)
                raise RuntimeError(f'API request failed: {response.status_code} ({response.reason})', response.content)
            print('.', end="", flush=True) # print a dot for every call to show activity
            return response.json()

    def getSecurityProblemsByCVE(self, cveID):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?pageSize=500&securityProblemSelector=cveId("'+cveID+'")')

    def __querySecurityProblems(self, endpoint):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        securityProblems = []
        response = self.queryApi(endpoint)
        securityProblems += response["securityProblems"]
        while("nextPageKey" in response):
            response = self.queryApi('/api/v2/securityProblems?nextPageKey='+response["nextPageKey"])
            securityProblems += response["securityProblems"]
        return securityProblems

    def getSecurityProblemDetails(self, securityProblemId):
        """
        gets the details for a specific security problem
        """
        return self.queryApi('/api/v2/securityProblems/'+securityProblemId+'?fields=%2BrelatedEntities,%2BriskAssessment,%2BaffectedEntities')
    
    def getProcesses(self, processeIDs):
        """
        Retrieves the details of the specfied processes, with thechnolgy details and the relations to software components
        :param list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        entities = []
        # split the list into chunks of 100 in order to avoid too large requests (URI too long)
        listOfGroupedIds = self.splitIntoChunks(processeIDs, 100)
        for ids in listOfGroupedIds:
            idSelector = ','.join(ids)
            entities += self.getAllEntities('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties.processType,properties.softwareTechnologies,properties.installerVersion,fromRelationships.isProcessOf&from=now-1h' + '&entitySelector=entityId('+idSelector+')')
        return entities
    
    def getAllEntities(self, endpoint):
        """
        Retrieves all entities by the specified api call (handles paging of results)
        param: str endpoint: the API endpoint to call
        return: list of entities (dictionary) 
        """
        entities = []
        response = self.queryApi(endpoint)
        entities += response["entities"]
        while("nextPageKey" in response):
            response = self.queryApi('/api/v2/entities?nextPageKey='+response["nextPageKey"])
            entities += response["entities"]
        return entities
    
    def splitIntoChunks(self, lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]


def getTechnologieVersion(process, technolotyType):
    """
    Gets the technology information from a process
    param: dictionary entity: the process entity from which the information should be retrieved
    return string: technology version
    """
    softwareTechnologies = process['properties']['softwareTechnologies']
    for technology in softwareTechnologies:
        if technology['type'] == technolotyType and 'version' in technology:
            return technology['version']


dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

with open('spring4shellexport.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['process.name', 'process.id', 'java.version', 'tomcat.version']
    writer.writerow(header)

    # retireve all security problems
    securityProblems = dynatraceApi.getSecurityProblemsByCVE(cve)

    # if the details flag is set, retrieve the details for every security problem
    # write result to a CSV file

    for secP in securityProblems:
        securityProblemDetail = dynatraceApi.getSecurityProblemDetails(secP["securityProblemId"])
        processes = dynatraceApi.getProcesses(securityProblemDetail['affectedEntities'])
        for process in processes:
            javaVersion = getTechnologieVersion(process, 'JAVA')
            if javaVersion:
                javaMajor = javaVersion.split('.')[0]
            tomcatVersion = getTechnologieVersion(process, 'APACHE_TOMCAT')
            if tomcatVersion:
                tomcatMajor = tomcatVersion.split('.')[0]

            if not filter or (javaMajor is not None and int(javaMajor) >= 9) and (tomcatVersion is not None) :
                writer.writerow([process['displayName'],
                    process['entityId'],
                    javaVersion,
                    tomcatVersion
                    ])

