from ast import walk
import os
import yara
import json
import hashlib

#bien i se lay ra tung file, output cuoi cung ghi ra file
global output, i
output =  {}

#ham se duoc goi khi fil da match voi rule
def matched_rule(data):
    path_file = i
    head, tail = os.path.split(path_file)
    #ghi vao output
    if tail not in output:
        output[tail] = {}
        output[tail]["path_full"] = head
        output[tail]["created_date"] = os.path.getctime(path_file)
        output[tail]["modified_date"] = os.path.getmtime(path_file)
        output[tail]["last_accessed_date"] = os.path.getatime(path_file)
        f = open(path_file, "rb")
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
file_path = input("Input directory for scanning: ")
list_file = []

#duyet tat ca file va luu vao list_file[]
for (root, dirs, files) in os.walk(file_path, topdown=True):
    for i in files:
        path_f = root + "\\" + i
        list_file.append(path_f)

#load tung yara rule voi tung file
for (root1, dirs1, rules1) in os.walk(r"compiled_rule", topdown=True):
    for i in list_file: #Lay ra tung file 
        for j in rules1: #Load ra tung rule
            path_rule = ""
            path_rule = root1 + "\\" + j
            rule = yara.load(path_rule)
            #kiem tra tung rule co match hay khong, neu match thi goi ham matched_rule
            matches = rule.match(i, callback=matched_rule, which_callbacks=yara.CALLBACK_MATCHES) 

#ghi ra file
with open("ouput.json", "w") as f1:
    output = json.dumps(output, indent = 4)
    f1.write(output)
    f1.close()
input("wait for enter to exit")