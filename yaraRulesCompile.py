from asyncio.windows_events import NULL
from itertools import count
from re import I
import yara
import os

#Dung de compile yara rule va save lai
for (root,dirs,files) in os.walk("yara",topdown=True):
    for i in files:
        try:
            rule_path = ""
            rule_path = str(root+"\\"+i)
            rules = yara.compile(rule_path)
            name = os.path.splitext(i)
            path_save = r"compiled_rule" + r"\\" + name[0] + r".txt"
            f = open(path_save, "w")
            rules.save(path_save)
            f.close()
        except:
            continue