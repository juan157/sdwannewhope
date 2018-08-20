#!/usr/bin/python3

import sys
import csv
import json

def write_result_to_csv_file(res, fname):
    with open(fname,mode="w") as fc:
        writer = csv.DictWriter(fc, fieldnames=res[0].keys())
        writer.writeheader()
        for r in res:
            writer.writerow(r)


def delete_build(dver):
    if dver == None: return dver

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

def group_by_version(rdict):

    res = {}

    for e in rdict:
        if e["additional_info"] is None or e["additional_info"] == "None": continue
        version = delete_build(e["additional_info"])
        key = version+";"+e["product"]
        if key in res.keys():
            res[key]["ip_list"] += ","+e["ip"]
        else:
            res[key] = {"vendor":e["vendor"], "product":e["product"], "ip_list":e["ip"]}

    return res



def main():
    if len(sys.argv) < 3: 
        print("Usage: "+sys.argv[0]+" <JSON file with markers> <output CSV file>\n")
        sys.exit(1)

    with open(sys.argv[1]) as js:
        raw_dict_str = js.read()

    raw_dict = json.loads(raw_dict_str)

    gr_dict = group_by_version(raw_dict)

    final_res = [{"vendor":value["vendor"], "product":key.split(";")[1],"additional_info":key.split(";")[0], "ip_list":value["ip_list"], "hosts_amount":len(value["ip_list"].split(","))} for key, value in gr_dict.items()]

    write_result_to_csv_file(final_res, sys.argv[2])

    sys.exit(0)

if __name__=="__main__":
    main()
