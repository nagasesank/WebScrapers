import selenium
import requests
import json
from xml.etree import ElementTree as ET
import sys
import lxml.html
import requests
from unittest import result
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.firefox.service import Service
newfileorfolder=sys.argv[1]
#path to the file containing xml code
def get(url: str) -> str:
    '''
    Request the URL and return the Response
    params:
        url: Type str
        rtype: str
    '''
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36'
    }
    response = requests.get(url, headers=headers).text
    return response
def gitlab_ver_check(newfile):
    with open(newfile, 'r') as file:
            data = file.read().encode()
    xmlfileread = lxml.html.fromstring(data).xpath('//definition[@class="vulnerability"]//reference[@source="VENDOR"]/@ref_url')[0]
    cveno=lxml.html.fromstring(data).xpath('//definition[@class="vulnerability"]//reference[@source="CVE"]/@ref_id')[0]
    rule_version=lxml.html.fromstring(data).xpath('//subexpression/text()')
    # print(xmlfileread,cveno)
    # print(rule_version)

    # Define the URL
    url = xmlfileread
    response = requests.get(url.replace('blob', 'raw'))
    data = response.json()

    version_info = None
    if data.get('data_version'):
        version_value = data['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'][0]['version_value']
        version_pairs=[v.strip() for v in version_value.replace('>=', '').replace('<', '').split(',')]
    else:
        gitlab_version = data['containers']['cna']['affected'][0]['versions']

        version_pairs = []

        for version_info in gitlab_version:
            version_value = version_info['version']
            less_than_value = version_info['lessThan']
            version_pairs.extend([version_value, less_than_value])

        # print(version_pairs)
    
    if rule_version == version_pairs:
         print(f"{cveno} => Rule Versions Matches Advisory Versions")
    else:
        print(f"{cveno} => Version is not found in the data.")

    
gitlab_ver_check(newfileorfolder)