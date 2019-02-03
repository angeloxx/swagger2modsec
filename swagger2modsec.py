#!/usr/bin/python

import logging, sys, re, os, json, requests, io, yaml, coloredlogs
from optparse import OptionParser
from py_essentials import hashing as hs
from swagger import Swagger

# Sample
# https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/petstore-with-external-docs.json

#############################################
# vars
#############################################
ruleId = 1

#############################################
# logger
#############################################
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') 
logger = logging.getLogger('swagger2modsec')
logger.setLevel(logging.INFO)

#############################################
# opts
#############################################
parser = OptionParser()
parser.add_option("-i", "--input", dest="infile", help="Input file or HTTP(s) URL", default="in.json")
parser.add_option("-o", "--output", dest="outfile", help="Output file", default="out.conf")
# parser.add_option("-y", "--output-yaml", dest="outfile_yaml", help="Yaml outfile for tester container", default="out.yaml")
parser.add_option("--block-action", dest="blockaction", help="Set the default block action", default="deny")
parser.add_option("--tag", dest="tag", help="Set the rules base tag", default="SWAGGER")
parser.add_option("-v", dest="verbose", help="Set the verbose flag", action="store_true", default=False)
parser.add_option("--no-color", dest="nocolor", help="Disable colored logs", action="store_true", default=False)
parser.add_option("-f", "--filter-path", dest="filterpath", help="Filtered paths (use multiple times), like /something", default=[], action="append")
parser.add_option("-s", "--start-from", dest="startfrom", help="Start from this modsecurity rule id (see https://www.modsecurity.org/CRS/Documentation/ruleid.html)", default=10000, type=int)
(options, args) = parser.parse_args()

ruleId = int(options.startfrom)

#############################################
# fn
#############################################
class cfile(io.FileIO):
    #subclass file to have a more convienient use of writeline
    def __init__(self, name, mode = 'r'):
        self = io.FileIO.__init__(self, name, mode)

    def writeline(self, string):
        self.write("{}\n".format(string).encode()) 
        return None

def printFormattedRule(a,b,c,d):
    global outFile
    global ruleId

    if c != "":
        c = "\"{}\"".format(c)
    outFile.writeline( "{:<10} {:<20} {:<40} \"{}\"".format(a,b,c,d))
    if "id:" in d:
        ruleId = ruleId + 1

def printComment(string):
    global outFile
    outFile.writeline( "# {}".format(string))

def printWhiteline():
    global outFile
    outFile.writeline("")

def printBanner(infile, swagger):
    global outFile
    outFile.writeline("# This file is auto-generated with swagger2modsec script and is based on")
    outFile.writeline("# swagger input file {}".format(infile))
    outFile.writeline("# SHA256 hash {}".format(swagger.checksum))
    printWhiteline()

#############################################
# pre-flight check
#############################################
if options.verbose:
    if not options.nocolor:
        coloredlogs.install(level='DEBUG', logger=logger)
    logger.setLevel(logging.DEBUG)
    logger.debug("Debug level enabled")
else:
    if not options.nocolor:
        coloredlogs.install(level='INFO', logger=logger)

if options.infile.startswith("http") and "//" in options.infile:
    # Download file
    try:
        r = requests.get(options.infile)
        with open("in.json", 'wb') as f:  
            f.write(r.content)
    except Exception as e:
        logger.error("Error retreiving file {0}".format(options.infile))
        logger.error("                      {0}".format(str(e)))
        sys.exit(1)
    swagger = Swagger("in.json", logger)
else:
    if not os.path.exists(options.infile):
        logger.error("Unable to open input file {0}".format(options.infile))
        sys.exit(1)
    swagger = Swagger(options.infile, logger)

logger.info("Swagger input file readed")

blockAction = options.blockaction.lower()

outFile = cfile(options.outfile,"w")
printBanner(options.infile,swagger)

printFormattedRule("SecAction","","","id:{0},phase:request,t:none,log,setenv:'isValidURI=No'".format(ruleId,blockAction))

for endpoint in swagger.getEndpoints():

    skipPath = False
    for filteredpath in options.filterpath:
        if endpoint.startswith(filteredpath):
            skipPath = True

    if skipPath:
        continue

    # Filter methods
    methods = swagger.getEndpointMethods(endpoint)
    endpointURI = swagger.endpointRequestURI(endpoint)

    printComment("{:#<76}".format(endpoint + " "))

    # ValidURI Flag
    tag = "{}/WHITELIST_URI".format(options.tag)
    printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',setenv:'isValidURI=Yes'".format(ruleId,tag,blockAction))
    printWhiteline()

    tag = "{}/METHOD_NOT_ALLOWED".format(options.tag)
    printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',{2},chain".format(ruleId,tag,blockAction))
    printFormattedRule("SecRule","REQUEST_METHOD","!^({})$".format("|".join(methods)).upper(),"t:none")

    printWhiteline()

    for method in methods:

        tag = "{}/PARAMETER_NAME_VALIDATION".format(options.tag)
        printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',{2},chain".format(ruleId,tag,blockAction))
        printFormattedRule("SecRule","REQUEST_METHOD",method.upper(),"t:none,chain")

        arguments = swagger.getEndpointArguments(endpoint,method)
        printFormattedRule("SecRule","ARGS_NAMES","!^({})$".format("|".join(arguments)),"t:none")
        printWhiteline()

        tag = "{}/PARAMETER_TYPE_VALIDATION".format(options.tag)
        for argument in arguments:
            validator = swagger.getEndpointURIParameterValidator(endpoint,argument,method)
            if validator != "":

                printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',{2},chain".format(ruleId,tag,blockAction))
                printFormattedRule("SecRule","REQUEST_METHOD",method.upper(),"t:none,chain")

                printFormattedRule("SecRule","ARGS:{}".format(argument),"!^({})$".format(validator),"t:none")
                printWhiteline()


# Print deny-all rule
tag = "{}/DENY_ALL".format(options.tag)
printFormattedRule("SecRule","ENV:isValidURI","No","id:{0},phase:request,t:none,log,tag:'{1}',{2}".format(ruleId,tag,blockAction))
ruleId = ruleId + 1
printWhiteline()

outFile.close()

