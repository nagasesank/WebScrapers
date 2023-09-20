import cveprey,sys
from lxml import html


cve_no=sys.argv[1]
print(cve_no)
rule_cve=sys.argv[2]
f=open(rule_cve,'r')
content = f.read()
f.close()
tree = html.fromstring(content.encode('utf-8'))

cve=cveprey.CVE(cve_no)
cve.get_nvd_data()
splunk_adv = cveprey.splunkAdvisories(cve.nvd_data.adv_links[0])

cvrf = splunk_adv.versions
versions=cvrf['Splunk Enterprise']
cve_data = [version for item in versions for version in item.split(' to ')]
print("CVE Versions From Advisory: ",cve_data)
rule_less_version=set(sorted(tree.xpath('//*[@operation="less than or equal"]/text()')))
rule_greater_version=set(sorted(tree.xpath('//*[@operation="greater than or equal"]/text()')))

if (set(cve_data).difference(set(rule_less_version)) == set(rule_greater_version)) and (set(cve_data).difference(set(rule_greater_version)) == set(rule_less_version)):
    print("Rule is Vaild")
else:
    print("Versions are Miss Match")
    print("lesser versions",rule_less_version)
    print("Greater versions",rule_greater_version)