#!/usr/bin/python

import logging, sys, re, os, json, requests, time, yaml, coloredlogs, docker
from optparse import OptionParser
from swagger import Swagger

#############################################
# vars
#############################################
mockServer = {"image": "palo/swagger-api-mock:latest", "name": "swagger-mockserver", "port": 8000, "is_running": False, "container_id": "" }
proxyServer = {"image": "angeloxx/modsecurity-crs-rp:v3.1", "name": "swagger-proxyserver", "port": 8001, "is_running": False, "container_id": "" }

#############################################
# logger
#############################################
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') 
logger = logging.getLogger('testcontainer')
logger.setLevel(logging.INFO)

#############################################
# fns
#############################################
class Tester: 
    def __init__(self, port):
        self.port = port
        self.lastRequestId = "N/A"

    def getLastRequestId(self):
        return self.lastRequestId

    def testGET(self, url, rule = ""):
        # Remove initial "/"
        if url.startswith("/"):
            url = url[1:]

        if rule != "":
            logger.info("Testing /{0}".format(url))

        try:
            r = requests.get("http://localhost:{0}/{1}".format(self.port,url))
        except Exception as e:
            self.lastRequestId = "N/A"
            if rule != "":
                logger.error("{0}".format(e))
            else:
                # Suppress error
                pass
            return -1

        if rule != "":
            logger.info("Testing /{0}".format(url))


        self.lastRequestId = r.headers["X-Request-ID"]
        return r.status_code


def getLog(requestId):
    if proxyServer["container_id"] == "":
        for container in dockerClient.containers.list():
            if container.attrs["Name"][1:] == proxyServer["name"]:
                proxyServer["container_id"] = container.attrs["Id"]

    exe = dockerApi.exec_create(container=proxyServer["container_id"], cmd="grep {} /var/log/apache2/error.log".format(requestId))
    exe_start = dockerApi.exec_start(exec_id=exe, stream=True)
    for val in exe_start:
        for line in "".join( chr(x) for x in val).split("\n"):
            if line != "":
                logger.info("{0}: {1}".format(requestId, line))

#############################################
# opts
#############################################
parser = OptionParser()
parser.add_option("-v", dest="verbose", help="Set the verbose flag", action="store_true", default=False)
parser.add_option("--no-color", dest="nocolor", help="Disable colored logs", action="store_true", default=False)
parser.add_option("-i", "--input", dest="infile", help="Input Swagger Json file or HTTP(s) URL", default="in.json")
#parser.add_option("-y", "--input-yaml", dest="input_yaml", help="Yaml input file for mock container", default="out.yaml")
parser.add_option("-r", "--input-ruleset", dest="input_ruleset", help="ModSecurity ruleset input file for proxy container", default="out.conf")
parser.add_option("--no-restart", dest="no_restart", help="Don't restart containers, just verify that are running and continue with tests", action="store_true", default=False)
(options, args) = parser.parse_args()

if not options.nocolor:
    coloredlogs.install(level='INFO', logger=logger)

swagger = Swagger(options.infile, logger)

input_ruleset = options.input_ruleset
if not input_ruleset.startswith("/"):
    input_ruleset = os.path.abspath(input_ruleset)

if not os.path.exists(input_ruleset):
    logger.error("Unable to open input file {0}".format(input_ruleset))
    sys.exit(1)


swagger.exportYaml("swagger.yaml")
input_yaml = os.path.abspath("swagger.yaml")
if not os.path.exists(input_yaml):
    logger.error("Unable to open converted swagger file {0}".format(input_yaml))
    sys.exit(1)

logger.info("YAML converted file is {0}".format(input_yaml))
logger.info("Ruleset input file is {0}".format(input_ruleset))

tester = Tester(proxyServer["port"])

try:
    dockerClient = docker.from_env()
    dockerApi = docker.APIClient(base_url='unix://var/run/docker.sock')
except Exception as e:
    logger.error("unable to get Docker interface")
    logger.error("{0}".format(e))
    sys.exit(1)

# Stop running containers or verify if it is running
for container in dockerClient.containers.list():
    containerName = container.attrs["Name"][1:]
    if containerName in (mockServer["name"],proxyServer["name"]):
        if not options.no_restart:
            logger.info("Stopping previous running container: {} (image {})".format(containerName, container.attrs['Config']['Image']))
            container.stop()
            container.remove()
        else:
            if containerName == mockServer["name"]:
                logger.info("Mock Server is already running: {} (image {}) on port {}".format(mockServer["name"], mockServer["image"],mockServer["port"]))
                mockServer["is_running"] = True
            if containerName == proxyServer["name"]:
                logger.info("Proxy Server is already running: {} (image {}) on port {}".format(proxyServer["name"], proxyServer["image"],proxyServer["port"]))
                proxyServer["is_running"] = True


# Start containers (if needed, required)
if not mockServer["is_running"]:
    logger.info("Starting Mock Server: {} (image {}) on port {}".format(mockServer["name"], mockServer["image"],mockServer["port"]))
    dockerClient.containers.run(
        mockServer["image"], 
        detach=True, 
        name=mockServer["name"],
        mounts=[ docker.types.Mount( source=input_yaml, target="/data/swagger.yaml", type="bind" ) ],
        ports={"{}/tcp".format(mockServer["port"]): mockServer["port"]}
        )

if not proxyServer["is_running"]:
    logger.info("Starting Proxy Server: {} (image {}) on port {}".format(proxyServer["name"], proxyServer["image"],proxyServer["port"]))
    dockerClient.containers.run(
        proxyServer["image"], 
        detach=True, 
        name=proxyServer["name"],
        mounts=[ docker.types.Mount( source=input_ruleset, target="/etc/apache2/modsecurity.d/owasp-crs/rules/swagger.conf", type="bind" ) ],
        ports={"{}/tcp".format(proxyServer["port"]): proxyServer["port"]}
        )
    # Wait few seconds
    waitCounter = 10
    while waitCounter > 0:
        if tester.testGET("/") > 0:
            waitCounter = -1
        else:
            time.sleep(1)
        waitCounter = waitCounter - 1

# Once containers are started, start tests
if tester.testGET("/") > 0:
    logger.info("OK, web server is ready")
else:
    logger.error("Web sever is not ready, abort")
    sys.exit(1)

for endpoint in swagger.getEndpoints():
    methods = swagger.getEndpointMethods(endpoint)
    endpointURI = swagger.endpointRequestURI(endpoint)

    logger.info("== URL {}".format(endpoint))
    if "get" in methods:
        # Test simple GET request
        r = tester.testGET(endpoint)
        if r >=200 and r < 400:
            logger.info("{}: Tested '{}', expected 200 returned {}".format(tester.getLastRequestId(), endpoint, r))
        else:
            logger.warning("{}: Tested '{}', expected 200 returned {}".format(tester.getLastRequestId(), endpoint, r))
            if options.verbose:
                getLog(tester.getLastRequestId())