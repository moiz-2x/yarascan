from ast import walk
import os
import yara
import json
import hashlib

#bien i se lay ra tung file, output cuoi cung ghi ra file
global output, file_path
output =  {}

#ham se duoc goi khi fil da match voi rule
def matched_rule(data):
    head, tail = os.path.split(file_path)
    #ghi vao output
    if tail not in output:
        output[tail] = {}
        output[tail]["path_full"] = head
        output[tail]["created_date"] = os.path.getctime(file_path)
        output[tail]["modified_date"] = os.path.getmtime(file_path)
        output[tail]["last_accessed_date"] = os.path.getatime(file_path)
        f = open(file_path, "rb")
        raw_data = f.read()
        f.close()
        output[tail]["md5"] = hashlib.md5(raw_data).hexdigest()
        output[tail]["sha256"] = hashlib.sha256(raw_data).hexdigest()
        output[tail]["sha1"] = hashlib.sha1(raw_data).hexdigest()
        output[tail]["rule"] = []
    output[tail]["rule"].append(data['rule'])
    output[tail]["reason"+"_"+data['rule']] = data["strings"]
    
    length_strings = len(output[tail]["reason"+"_"+data['rule']])
    
    #chuyen doi kieu du lieu de dung ham json.dumps()
    for z in range (length_strings):
        output[tail]["reason"+"_"+data['rule']][z] = list(output[tail]["reason"+"_"+data['rule']][z])
        output[tail]["reason"+"_"+data['rule']][z][2] = str(output[tail]["reason"+"_"+data['rule']][z][2])

#input path
input_path = input("Input directory for scanning: ")

list_rule = []
#Dung de compile yara rule
for (root,dirs,files) in os.walk("yara",topdown=True):
    for z in files:
        try:
            rule_path = ""
            rule_path = str(root+"\\"+z)
            list_rule.append(yara.compile(rule_path))
        except:
            continue

#duyet tat ca file kiem tra
for (root, dirs, files) in os.walk(input_path, topdown=True):
    for i in files:
        file_path = ''
        file_path = str(root+"\\"+i)
        for rule in list_rule:
            #kiem tra tung rule co match hay khong, neu match thi goi ham matched_rule
            matches = rule.match(file_path, callback=matched_rule, which_callbacks=yara.CALLBACK_MATCHES) 
        

#ghi ra file
with open("ouput.json", "w") as f1:
    output = json.dumps(output, indent = 4)
    f1.write(output)
    f1.close()

input("wait for enter to exit")