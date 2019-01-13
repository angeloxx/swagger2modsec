#!/usr/bin/python

import logging, sys, re, os, json, requests, io
from optparse import OptionParser
from py_essentials import hashing as hs

# Sample
# https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/petstore-with-external-docs.json

#############################################
# vars
#############################################
ruleId = 1

#############################################
# logger
#############################################
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logging.getLogger('swagger2modsec').setLevel(logging.ERROR)

#############################################
# opts
#############################################
parser = OptionParser()
parser.add_option("-i", "--input", dest="infile", help="Input file or HTTP(s) URL", default="in.json")
parser.add_option("-o", "--output", dest="outfile", help="Output file", default="out.conf")
parser.add_option("--block-action", dest="blockaction", help="Set the default block action", default="deny,status:406")
parser.add_option("--tag", dest="tag", help="Set the rules base tag", default="SWAGGER")
parser.add_option("-f", "--filter-path", dest="filterpath", help="Filtered paths (use multiple times), like /something", default=[], action="append")
parser.add_option("-s", "--start-from", dest="startfrom", help="Start from this modsecurity rule id (see https://www.modsecurity.org/CRS/Documentation/ruleid.html)", default=10000, type=int)
(options, args) = parser.parse_args()

ruleId = int(options.startfrom)

#############################################
# fn
#############################################
class Swagger:
    def __init__(self, filename):
        self.endpoints = []
        self.checksum = ""
        self.filename = filename
        try:
            with open(self.filename) as json_file:  
                self.swagger = json.load(json_file)
    
        except Exception as e:
            logging.error("Error reading file: {0}".format(str(e)))
            sys.exit(1)


        self.checksum = hs.fileChecksum(self.filename, "sha256")
        self.__getEndpoints()

    def __getEndpoints(self):
        for path in self.swagger["paths"]:
            self.endpoints.append(path)

    def getEndpointMethods(self, endpoint):
        ret = []
        if not endpoint in self.swagger["paths"]:
            return ret
        
        for method in self.swagger["paths"][endpoint]:
            ret.append(method.toUpper())

        return ret

    def getEndpoints(self):
        return self.endpoints


    def getEndpointURIParameterValidator(self, _endpoint, _parameter, _method = ""):
        # NOTE: the validator for an URI parameter SHOULD be the same, the script
        # will use the FIRST match if method is empty and REQUIRED=false is not supported

        try:
            for method in self.swagger["paths"][_endpoint]:
                if method != "" or method == _method:
                    for parameterValue in self.swagger["paths"][_endpoint][method]["parameters"]:
                        if parameterValue["name"] == _parameter and "type" in parameterValue:
                            if parameterValue["type"] == "integer":
                                return "[0-9]+"
                            if parameterValue["type"] == "string":
                                return "[\w\s\d]+"

                            if parameterValue["type"] == "number":
                                if parameterValue["format"] == "double":
                                   return "(-?)(0|([1-9][0-9]*))(\\.[0-9]+)?"
        except Exception as e:
            logging.error("getEndpointURIParameterValidator({0},{1},{2})".format(_endpoint, _parameter, _method))
            logging.error("{0}".format(e))
            sys.exit(1)

        return ""

    def getEndpointArguments(self, _endpoint, _method):
        ret = []
        for parameterValue in self.swagger["paths"][_endpoint][_method]["parameters"]:
            ret.append(parameterValue["name"])

        return ret


    def endpointRequestURI(self, endpoint):
        if not "{" in endpoint:
            return "@streq {}".format(endpoint)


        endpointURI = endpoint.replace("/","\/")
        for parameter in re.findall("\{(\w+)\}",endpoint):
            validator = self.getEndpointURIParameterValidator(endpoint,parameter)
            endpointURI = endpointURI.replace("{0}".format("{"+parameter+"}"), validator)
        
        
        return "^{}$".format(endpointURI)

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

if options.infile.startswith("http") and "//" in options.infile:
    # Download file
    try:
        r = requests.get(options.infile)
        with open("in.json", 'wb') as f:  
            f.write(r.content)
    except Exception as e:
        logging.error("Error retreiving file {0}".format(options.infile))
        logging.error("                      {0}".format(str(e)))
        sys.exit(1)
    swagger = Swagger("in.json")
else:
    if not os.path.exists(options.infile):
        logging.error("Unable to open input file {0}".format(options.infile))
        sys.exit(1)
    swagger = Swagger(options.infile)


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
    printFormattedRule("SecRule","REQUEST_METHOD","!@within {}".format(" ".join(methods)),"t:none")

    printWhiteline()

    for method in methods:

        tag = "{}/PARAMETER_NAME_VALIDATION".format(options.tag)
        printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',{2},chain".format(ruleId,tag,blockAction))
        printFormattedRule("SecRule","REQUEST_METHOD",method,"t:none,chain")

        arguments = swagger.getEndpointArguments(endpoint,method)
        printFormattedRule("SecRule","ARGS_NAMES","!^({})$".format("|".join(arguments)),"t:none")
        printWhiteline()

        tag = "{}/PARAMETER_TYPE_VALIDATION".format(options.tag)
        for argument in arguments:
            validator = swagger.getEndpointURIParameterValidator(endpoint,argument,method)
            if validator != "":

                printFormattedRule("SecRule","REQUEST_URI",endpointURI,"id:{0},phase:request,t:none,log,tag:'{1}',{2},chain".format(ruleId,tag,blockAction))
                printFormattedRule("SecRule","REQUEST_METHOD",method,"t:none,chain")

                printFormattedRule("SecRule","ARGS:{}".format(argument),"!^({})$".format(validator),"t:none")
                printWhiteline()


# Print deny-all rule
tag = "{}/DENY_ALL".format(options.tag)
printFormattedRule("SecRule","ENV:isValidURI","No","id:{0},phase:request,t:none,log,tag:'{1}',{2}".format(ruleId,tag,blockAction))
ruleId = ruleId + 1
printWhiteline()

outFile.close()

