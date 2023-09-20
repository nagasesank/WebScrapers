import re,sys
import cveprey

cve= sys.argv[1]
rule=sys.argv[2]

ciscoAdv = cveprey.ciscoSecurityAdvisories()

adv= cveprey.ciscoAdvisories(cve, ciscoAdv.cveData(cve).adv_link)
cvrf_versions=adv.cvrf_contents()
cvrf_versions.export

print(cvrf_versions.affected_products)

class Versions():
    #this gives you the CVRF Versions
    def cvrf(self):
        self.versions_affected = {}
        for product in cvrf_versions.affected_products:
            try:
                if len(cvrf_versions.affected_versions) > 0:
                    versions=cvrf_versions.affected_versions
                    print("Total CVRF Versions")
                    self.versions_affected[product]=versions[product]['All']
                    print(f"{product} Versions:", len(self.versions_affected[product]))
                    print("-------------------------------------------------")
            except Exception:
                continue
            
    def cve(self):
        #this gives you the Definition Versions 
        fp = open(rule, 'r').read()
        fp = fp.encode('utf-8')
        print("Total Definition Versions")
        for keys in self.versions_affected:
            try:
                element = cveprey._core.lhtml.fromstring(fp)
                ids=element.xpath('//constant_variable/@id')
                if len(ids) > 1:
                    iosxe_ver=[i for i in element.xpath('//constant_variable/value/text()') if "^" in i]
                    print("IOSXE Versions:", len(iosxe_ver))
                    iosxe_mapped_ver = [i for i in element.xpath('//constant_variable/value/text()') if "^" not in i]
                    print("Mapped IOSXE Versions:",len(iosxe_mapped_ver))
                else:
                    ver = element.xpath('//constant_variable/value/text()')
                    cvrf = set(list(map(lambda x: x.upper(), self.versions_affected[keys])))
                    def_ver = set(list(map(lambda x: x.upper(), ver)))
                    #Compare the CVRF with Definition 
                    diff_cvrf_def_ver = cvrf.difference(def_ver)
                    print("Missed Versions:", len(diff_cvrf_def_ver))
                    print(f"{keys} Versions:", len(ver))

            except Exception:
                continue

obj = Versions()
obj.cvrf()
obj.cve()




