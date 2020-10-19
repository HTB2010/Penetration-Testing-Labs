#!/usr/bin/env python3
# By Ken Truong
# import sys let us interact with the system where the script is run (except input and append to the file on terminal)
# print("The first argument was: " + sys.argv[1]) # argv is a collection of arguments that this process is called with (calling environment)
import argparse
import requests
import validators
import yaml
from urllib.parse import urlparse # This module defines a standard interface to break Uniform Resource Locator (URL)
# strings up in components (addressing scheme, network location, path etc.), to combine the components back into a URL
# string, and to convert a “relative URL” to an absolute URL given a “base URL.
from bs4 import BeautifulSoup # Beautiful Soup is a Python library for pulling data out of HTML and XML files
from bs4 import Comment


parser = argparse.ArgumentParser(description="The Archilles HTML Vulnerability Analyzer Version 1.0")
# This is called a constructor for argparse class and takes a few things as arguments

parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0")
parser.add_argument("url",type=str, help="The URL of the HTML to analyze")
parser.add_argument("--config", help="Path to configuration file")
parser.add_argument("-o", "--output", help="Report file output path")
args = parser.parse_args()
# print(args.config)

config = {"forms": True, "comments": True, "passwords": True}

if(args.config):
    print("Using config file: " + args.config)
    config_file=open(args.config, "r")
    config_from_file = yaml.load(config_file)
    # this statemnet take the I/O stream from the file and pass it to yaml.load function and converted
    # to python object as long as it valid yaml, we are checking for forms, comments, and password_inputs
    # print(config)
    if(config_from_file):
        config = { **config, **config_from_file } # this is the format for merging two dictionaries together
        #** means that it expands out into a full dictionary and use
        # config_from_file as the second source of input
        # content from the config.yml will override the config statement from above(line 26)
report = ''

url = args.url

if (validators.url(url)):
    # print("That was a good URL")
    result_html = requests.get(url).text
    parsed_html = BeautifulSoup(result_html, "html.parser") # this takes the string from html_result and parsed them
    #print(result_html)
    #print(parsed_html)
    #print(parsed_html.title) # an object title is part of the property html document

    forms = (parsed_html.find_all("form"))
    comments = parsed_html.find_all(string=lambda text:isinstance(text,Comment)) # this is a special instruction to the
    # parser from the beautifulsoup # we want to perform a function inside of findall
    password_inputs = parsed_html.find_all("input", {"name" : "password"})

    if(config["forms"]): # only run this part of the code if config.forms is true
        for form in forms:
            if((form.get("action").find("https") < 0) and (urlparse(url).scheme != "https")): # if either the form itself
            # does not have a https action in it or the url from which we are getting the request pass by the user does
            # not have https already, we want to say that form_is_secure is False
            # form_is_secure = False
            # print(form_is_secure)
                report += 'Form Issue: Insecure form action' + form.get('action') + 'found in document\n'

    if(config["comments"]):
        for comment in comments:
            if(comment.find('key: ') > -1):
                report += "Comment Issues: Key is found in the HTML comments, please remove\n" #

    if(config["passwords"]):
        for password_input in password_inputs:
            if(password_input.get("type") != "password"):
                report += "Input Issue:  Plaintext password input found. Please change to password type input\n"
else:
    print("Invalid URL. Please include full URL including scheme.")

if(report == ""):
    # print("Nice job! Your HTML document is secure!")
    report += "Nice job! Your HTML document is secure!\n"
else:
    # print("Vulnerability Report is as follows:")
    header = "Vulnerability Report is as follows:\n"
    # print("======================================\n")
    header += "======================================\n\n"
    report = header + report

print(report)

if(args.output):
    #print(args.output)
    f = open(args.output, "w")
    f.write(report)
    f.close
    print("Report saved to: " + args.output)
# type python3 -m http.server
# python3 Basic_python.py http://localhost:8000 --config config.yml

