# Why?

In these days I'm looking for a fast way to create modsecurity validation rules starting from a swagger file. I found https://github.com/EP-Tribe/openapi-sec but is pretty useless in my case, so I've tried (in less that two hours, so is not a great script but is a starting point) to create a Python script to convert a swagger json to a small set of modsecurity rules. Many things are missing and probably I've to change the white/blacklist approach, but this is a idea for someone that have more time (and more interest) to create a useful tool to convert a well documented API descriptor to ModSecurity 2.x rule set. If you are using CRS you also have to whitelist needed rules.

# Installation

This script uses py_essentials and logging additional modules, but I didn't created the requirements.txt file at the moment. Libmodsecurity is not needed, but I know that pymodsecurity binding exists and can be used to validate rules and test it so I suggest to install:

    sudo apt install libmodsecurity-dev
    sudo pip3 install -r requirements.txt

and perform basic validatation with:

    /usr/lib/x86_64-linux-gnu/libexec/modsec-rules-check out.json

Remember that the only valid Linux distribution is Debian.

# Usage

## Create rules

    python3 swagger2modsec.py -i https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/uber.json
    python3 swagger2modsec.py -i https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/petstore-with-external-docs.json

## Test rules

You can use testcontainer.py script to test generated rules (TBD). This script:

* starts a Docker container that implements a backend web server (using swagge-api-mock) that implements the described api
* starts an Apache web server with modsecurity and CRS that proxies requests to the backend server and use generated rules
* performs requests against APIs (TBD) and reports Apache's error log to verify denied requests

## Generate rules with SAMPLE1.json data and test it


Create ruleset file:

    python3 swagger2modsec.py -i SAMPLE1.json -o SAMPLE1.conf
    swagger2modsec[8622] INFO Swagger input file readed


Test it (the second test fails because the test is incomplete, but I want to verify the log dump). You can user --no-restart to repeat the same test with same rule file without restart containers:

    python3 testcontainer.py -v -i SAMPLE1.json
    INFO YAML converted file is /data/swagger2modsec/swagger.yaml
    INFO Ruleset input file is /data/swagger2modsec/SAMPLE1.conf
    INFO Stopping previous running container: swagger-proxyserver (image angeloxx/modsecurity-crs-rp:v3.1)
    INFO Stopping previous running container: swagger-mockserver (image palo/swagger-api-mock:latest)
    INFO Starting Mock Server: swagger-mockserver (image palo/swagger-api-mock:latest) on port 8000
    INFO Starting Proxy Server: swagger-proxyserver (image angeloxx/modsecurity-crs-rp:v3.1) on port 8001
    INFO OK, web server is ready
    INFO == URL /pets
    INFO XFcBkEk76vJfj0adVvFalQAAAJY: Tested '/pets', expected 200 returned 200
    INFO == URL /pets/{id}
    WARNING XFcBkDubr3gToavZgzXkygAAAEg: Tested '/pets/{id}', expected 200 returned 403
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.902651] [authz_core:debug] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg AH01628: authorization result: granted (no directives)
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.919097] [-:error] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg [client 172.17.0.1] ModSecurity: Warning. Unconditional match in SecAction. [file     "/etc/apache2/modsecurity.d/owasp-crs/rules/swagger.conf"] [line "5"] [id "10000"] [hostname "localhost"] [uri "/pets/{id}"] [unique_id "XFcBkDubr3gToavZgzXkygAAAEg"]
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.919336] [-:error] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg [client 172.17.0.1] ModSecurity: Access denied with code 403 (phase 2). Pattern match "No" at ENV. [file "/etc/apache2/modsecurity.d/owasp-crs/rules/swagger.conf"] [line "46"] [id "10012"] [tag "SWAGGER/DENY_ALL"] [hostname "localhost"] [uri "/pets/{id}"] [unique_id "XFcBkDubr3gToavZgzXkygAAAEg"]
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.919621] [authz_core:debug] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg AH01626: authorization result of Require all granted: granted
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.919640] [authz_core:debug] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg AH01626: authorization result of <RequireAny>: granted
    INFO XFcBkDubr3gToavZgzXkygAAAEg: [2019-02-03 14:58:24.959251] [-:error] 172.17.0.1:44791 XFcBkDubr3gToavZgzXkygAAAEg [client 172.17.0.1] ModSecurity: Audit log: Failed to create subdirectories: /var/log/apache2/audit//20190203/20190203-1458 (Permission denied) [hostname "localhost"] [uri "/error/403.html"] [unique_id "XFcBkDubr3gToavZgzXkygAAAEg"]


# TODO

* implementation of rule tests
* better integration with docker api

# See also

* https://coreruleset.org/20181212/core-rule-set-docker-image/
* https://github.com/angeloxx/modsecurity-crs-rp forked image that returns X-Request-Id header