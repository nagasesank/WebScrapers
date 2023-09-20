import os
import subprocess
import shutil
import json,sys
import re
githuprepopath="<path of github repo>"
home=os.getcwd()
def pull():
        os.chdir(githuprepopath)
        os.system("git pull --no-ff && git fetch -p")
        global cves
        cves=list(set(re.findall("CVE-\d+-\d+",subprocess.getoutput('gh pr list --search "assignee:<username> sort:created-asc" -L 200 -l "issues"'))))
        os.chdir(home)
def downloadfile():
        pull()
        for i in cves:
            if os.path.exists(i):
                os.system("rm -rf "+i+"/*.xml")
            if not os.path.exists(i):
                os.makedirs(i)
            os.chdir(i)    
            subprocess.getoutput("ovaltools -C "+i)
            os.chdir(home)
downloadfile()
