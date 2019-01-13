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

    python3.5 swagger2modsec.py -i https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/uber.json
    python3.5 swagger2modsec.py -i https://raw.githubusercontent.com/OAI/OpenAPI-Specification/master/examples/v2.0/json/petstore-with-external-docs.json

# TODO

* integrate pymodsecurity to test syntax and block actions (based on standard pattern that breaks the swagger contract)