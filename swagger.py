#!/usr/bin/python
import logging, sys, re, os, json, requests, io, yaml, coloredlogs
from py_essentials import hashing as hs

class Swagger:
    def __init__(self, filename, logger):
        self.endpoints = []
        self.checksum = ""
        self.filename = filename
        self.logger = logger
        try:
            with open(self.filename) as json_file:  
                self.swagger = json.load(json_file)
    
        except Exception as e:
            self.logger.error("Error reading file: {0}".format(str(e)))
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
            ret.append(method)

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
            self.logger.error("getEndpointURIParameterValidator({0},{1},{2})".format(_endpoint, _parameter, _method))
            self.logger.error("{0}".format(e))
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


    def exportYaml(self,yamlfile):
        yamlfilecontent = yaml.dump(self.swagger, default_flow_style=False)
        with open(yamlfile, 'w') as f:
            f.write(yamlfilecontent)    