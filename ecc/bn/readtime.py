import re
def readtime():
    with open("./time.txt") as f:
        for line in f.readlines():
            m = re.search(r'(\d{1,3})  batch verification time:(.{6,8})',line.strip())
            num = 0;
            if m != None:
                print('if(count[i]==' + m.group(1) + '){')
                print('    rec[i]=' + m.group(2) + ';')
                print('    tt+=rec[i];')
                print('}')

if __name__ == '__main__':
    readtime()
