import selenium
from xml.etree import ElementTree as ET
import sys
import re
import time
import lxml.html
import requests
import scandir
import os
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
username="loginid"
password="password"
def orapatchl(newfile):
    osi=newfile.split("/")[-1].split("-")[3]
    product=newfile.split("/")[-1].split("-")[-1].split(".")[0]
    print(osi)
    with open(newfile, 'r') as file:
            data = file.read().encode()
    xmlfileread = lxml.html.fromstring(data).xpath('//definition[@class="vulnerability"]//reference[@source="VENDOR"]/@ref_url')[0]
    cveno=lxml.html.fromstring(data).xpath('//definition[@class="vulnerability"]//reference[@source="CVE"]/@ref_id')[0]
    patch_number = lxml.html.fromstring(data).xpath('//value_of[@datatype="version"]/text()')
    version_number=lxml.html.fromstring(data).xpath('(//subexpression/text()|//value_of[@datatype="string"]/text())')
    print("Rule Patches:",version_number, patch_number)
    x=get(xmlfileread)
    title = lxml.html.fromstring(x).xpath("//title/text()")[0]
    notfound = re.search("[Pp]age\s+not\s+found", title)
    if not notfound:
        patchurl = lxml.html.fromstring(x).xpath('//td/a[@href="#AppendixDB"][contains(text(),"Oracle Database Server")]/following::td[1]/a/@href')[0]
        print(patchurl,cveno)
        login="https://login.oracle.com/mysso/signon.jsp"
        # give the exact location for the geckodriver if error delete the snap firefox install firefox from website
        new_driver_path = '/home/surya/Downloads/CVE Writer/CVE-writer1/code/geckodriver'
        serv = Service(new_driver_path)
        options = FirefoxOptions()
        # options.add_argument("--headless")
        driver = webdriver.Firefox(service=serv,options=options)
        driver.get(patchurl)
        time.sleep(10)
        driver.find_element("id", "sso_username").send_keys(username)
        driver.find_element("id", "ssopassword").send_keys(password)
        driver.find_element("id", "signin_button").click()
        time.sleep(10)
        patch_adv=[]
        patches=driver.find_elements(by=By.XPATH, value='(//table[@rules="all"]//td[contains(text(),"'+cveno+'")]/preceding::td[1]|//table[@rules="all"]//td//p[contains(text(),"'+cveno+'")]/preceding::td[1])')
        for j in [i.text.split("\n") for i in patches]:
            for k in j:
                # print(k)
                if product == "db":
                    if any(ele in k for ele in ["Database Release Update","Database Update"]) and osi in ["lin","sol"] and all(ele not in k for ele in ["OJVM"]):
                        patch=re.findall("[Pp]atch\s+(\d+)",k)
                        patch_adv.append(min(patch))
                    if "Microsoft Windows" in k and osi=="win" and "OJVM" not in k:
                        patch=re.findall("[Pp]atch\s+(\d+)",k)
                        patch_adv.append(min(patch))
                elif product== "wls":
                    if any(ele in k for ele in ["WLS PATCH SET UPDATE","Weblogic Samples SPU"]) and osi=="win" and "OJVM" not in k:
                        patch=re.findall("[Pp]atch\s+(\d+)",k)
                        patch_adv.append(min(patch))
        
        if not patch_adv:
            for j in [i.text.split("\n") for i in patches]:
                print(j)
            newcve=input("Give the Addressing CVE: ").replace(" ","")
            patches=driver.find_elements(by=By.XPATH, value='(//table[@rules="all"]//td[contains(text(),"'+newcve+'")]/preceding::td[1]|//table[@rules="all"]//td//p[contains(text(),"'+newcve+'")]/preceding::td[1])')
            for j in [i.text.split("\n") for i in patches]:
                for k in j:
                    # print(k)
                    if product == "db":
                        if any(ele in k for ele in ["Database Release Update","Database Update"]) and osi in ["lin","sol"] and all(ele not in k for ele in ["OJVM"]):
                            patch=re.findall("[Pp]atch\s+(\d+)",k)
                            patch_adv.append(min(patch))
                        if "Microsoft Windows" in k and osi=="win" and "OJVM" not in k:
                            patch=re.findall("[Pp]atch\s+(\d+)",k)
                            patch_adv.append(min(patch))
                    elif product== "wls":
                        if  any(ele in k for ele in ["WLS PATCH SET UPDATE","Weblogic Samples SPU"]) and osi=="win" and "OJVM" not in k:
                            patch=re.findall("[Pp]atch\s+(\d+)",k)
                            patch_adv.append(min(patch))
        driver.close()
        driver.quit()
        patch_adv.sort()
        patch_number.sort()
        if list(set(patch_adv))==list(set(patch_number)):
            print("Patches are Correct "+str(list(set(patch_adv))))
        else:
            print("Actual Patch Found "+str(list(set(patch_adv)))+" But Written "+str(list(set(patch_number))))

def orapatchcheck(newfileorfolder):
    if os.path.isfile(newfileorfolder):
        orapatchl(newfileorfolder)
    else:
        for paths, dirs, files in scandir.walk(newfileorfolder):
            for file in files:
                    orapatchl(os.path.join(paths, file))
                    time.sleep(10)

    
orapatchcheck(newfileorfolder)
