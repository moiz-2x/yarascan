import concurrent.futures
import os
import yara
import json
import hashlib
import argparse

 
global file_path, output
output = {}

#ham se duoc goi khi file da match voi rule
def matched_rule(data):
    global file_path
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

#ham xu ly file non-ascii
def remove_non_ascii_1(text):
    return ''.join([i if ord(i) < 128 else 'a' for i in text])

#ham thuc thi scan chinh
def yaraScan(args, list_rule):
    input_path = args.inp
    
    #duyet tat ca file kiem tra
    #bien i se lay ra tung file
    for (root, dirs, files) in os.walk(input_path, topdown=True):
        for i in files:
            global file_path
            file_path = ''
            file_path = str(root+"\\"+i)
            #kiem tra tung rule co match hay khong, neu match thi goi ham matched_rule
            if(i.isascii() == False):
                file_data=""
                with open (file_path, "rb") as sampleFile:
                    file_data = sampleFile.read()
                    sampleFile.close()
                new_file_path = root + "\\" + remove_non_ascii_1(i)
                with open(new_file_path, "wb") as sampleFile:
                    sampleFile.write(file_data)
                    sampleFile.close()
                for rule in list_rule:
                    matches = rule.match(new_file_path, callback=matched_rule, which_callbacks=yara.CALLBACK_MATCHES)
                os.remove(new_file_path)
            else:
                for rule in list_rule:
                    matches = rule.match(file_path, callback=matched_rule, which_callbacks=yara.CALLBACK_MATCHES) 

#ham viet vao file json
def write_json(args):
    #ghi ra file
    global output
    if args.outp == "output.json":
        with open(args.outp, "w", encoding="utf8") as f1:
            output = json.dumps(output, indent = 4, ensure_ascii=False)
            f1.write(output)
            f1.close()
    else:
        output_file = args.outp + "\\" + "output.json"
        with open(output_file, "w", encoding="utf8") as f1:
            output = json.dumps(output, indent = 4, ensure_ascii=False)
            f1.write(output)
            f1.close()
    
    input("wait for enter to exit")

#Ham dung de compile rule
def rule_compile():
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
    return list_rule

#ham tao parser
def make_parser():
    #cau hinh cac flag
    parser = argparse.ArgumentParser(description='Yara scan tool')
    parser.add_argument('scan')
    parser.add_argument('-inp', help='input path to scan')
    parser.add_argument('-outp', help='output path file json', nargs='?', default='output.json')
    args = parser.parse_args()
    return args

if __name__ == "__main__":
    #Tao 1 thread compile rule va 1 threat tao parser
    with concurrent.futures.ThreadPoolExecutor() as executor:
        Thread_ruleCompile = executor.submit(rule_compile)
        Thread_makeParser = executor.submit(make_parser)
        yaraScan(Thread_makeParser.result(), Thread_ruleCompile.result())
        write_json(Thread_makeParser.result())
    


    
    