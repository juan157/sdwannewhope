#!/usr/bin/env python3

import shodan
import sys
import json
import copy
import csv
import re
import nmap

API_KEY = "ACTUAL_SHODAN_API_KEY"


def write_result_to_file_json(res):
    
    if len(res) == 0 or res is None: return None

    with open("result.json","w") as fr:
        fr.write(json.dumps(res))

		
def write_result_to_file_csv(res):
    
    if len(res) == 0 or res is None: return None
    
    with open("result.csv",mode="w") as fc:
        writer = csv.DictWriter(fc, fieldnames=res[0].keys())
        writer.writeheader()
        for r in res:
            writer.writerow(r)


def add_to_array(res,res_csv, elem):

    for r in res:
        if elem["ip"] == r["ip"]: break
    else:
        res.append(copy.deepcopy(elem))

    for r in res_csv:
        if elem["ip"] == r["ip"] and elem["port"] == r["port"]: break
    else:
        res_csv.append(copy.deepcopy(elem))

    return None


def nmap_script_exec(nm, ip, port, script):

    res = nm.scan(ip, str(port), arguments='-Pn --script=../nse-scripts/'+script)
    script_name = script.split(".")[0]
    raw_script = res["scan"][ip]["tcp"][port].get("script")
    if raw_script is None: return None
    raw_version = raw_script[script_name]
    version_index = raw_version.find("Version:")
    if version_index == -1: return None
    version = raw_version[version_index+len("Version: "):]
    return version


def get_info(nm, script, vendor,elem):

    if "silver peak systems" == vendor.lower():
        data = elem.get("data")
        if data is not None and "VXOA " in data: return data.encode("utf-8","ignore")

        tmp_http = elem.get("http")
        if tmp_http is not None: 
            redirects = tmp_http.get("redirects")
            if len(redirects) == 0: return None
            rdata = redirects[0].get("data")
            m = re.search(r"Location:\s*\/([0-9_.]+)\/", rdata)
            if m:
                return m.group(1)

    elif "arista" == vendor.lower():
        data = elem.get("data")
        if data is not None and "EOS " in data:
            version_index = data.find("EOS version ")
            version_index_end = data.find(" running")
            if version_index == -1: return None
            version = data[version_index+len("EOS version "):version_index_end]
            return version
    else:
        if str(elem.get("port")) in ["80", "443", "8080"] and len(script) > 0:
            return nmap_script_exec(nm, elem.get("ip_str"), elem.get("port"),script)


def delete_build(dver):
    if dver is None: return dver

    spl_ = dver.split("_")
    splr = dver.split("r")
    spld = dver.split(".")
    splm = dver.split("-")
    
    if dver[:2] == "r7": return dver[1]+"."+dver[3]
    if len(splm) > 2: return splm[-1].split("r")[0]
    if len(splr) == 2 and len(splr[0]) > 0 and len(splr[1]) > 0: return splr[0]
    if len(spl_) == 2: return spl_[0]
    if len(spld) > 3 and len(spld[3]) > 4: return '.'.join(spld[:-2])

    return dver


def main():

    if len(sys.argv) == 1:
        print('Usage: %s <File which includes Shodan Queries>' % sys.argv[0])
        sys.exit(1)

    api = shodan.Shodan(API_KEY)
    nm = nmap.PortScanner()
    result = []
    result_csv = []

    with open(sys.argv[1]) as fp:
        queries = json.loads(fp.read())

    for q in queries:
        try:
            print(q["product"]+" found: "+ str(api.count(q["query"]).get("total")))
            cur = api.search_cursor(q["query"])
            for c in cur:
                if c["location"]["latitude"] is None or c["location"]["longitude"] is None: continue
                add_to_array(result, result_csv, {"product": q["product"], "vendor": q["vendor"], "port": c.get("port"),
                                   "proto": c["_shodan"]["module"], "ip": c.get("ip_str"),
                                   "lat": c["location"]["latitude"], "lng": c["location"]["longitude"], "additional_info":delete_build(str(get_info(nm, q["script"], q["vendor"], c)))})

        except Exception as e:
            print("Error: %s" % e)
            if len(result) == 0: break
            continue

    print("Final result (unique hosts): "+str(len(result)))
    print("Final result (unique pairs host and port): "+str(len(result_csv)))
    write_result_to_file_json(result)
    write_result_to_file_csv(result_csv)
    

if __name__ == "__main__":
    main()
