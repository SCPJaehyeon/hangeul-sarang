import os
import sys
from tqdm import tqdm
from time import sleep

import zlib # zlib 디컴프레스 위한
from io import BytesIO # 바이트 io 위한
import olefile # OLE 파서 이용

#byte의 값이 0인지pi 체크 ord의 매개변수가 0이면 에러남
def check(byte):
    if len(byte) != 0:            
        return ord(byte)
    else:
        return 0
# 진행 상황 알려줌 
def printProgressBar (iteration, total, prefix = '', suffix = '', decimals = 1, length = 100, fill = '█'):

    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print('\r%s |%s| %s%% %s' % (prefix, bar, percent, suffix), end = '\r')
    # Print New Line on Complete
    if iteration == total: 
        print()

## main

file_num = 2000 # 전체 파일의 개수 
total = 0 # 특정 바이트 값의 빈도수 총합 (전체 파일) 
total_lst = [0 for _ in range(256)] #헥사 빈도 총합 리스트 
result_lst = [0 for _ in range(256)] #결과 값 리스트 
file_lst = []
file_cnt =0
path = r"C:\Users\SayNot\Desktop\hwp_originfile"
except_cnt = 0

print("파일 탐색중..")
filenames = os.listdir(path)
print("디렉토리 내의 파일갯수 : {0}".format(len(filenames)))
if len(filenames) < file_num:
    exit()
for filename in filenames:
    file_lst.append(filename)
    file_cnt+=1
    if file_cnt == file_num:
        break
print("파일 탐색완료!")

printProgressBar(0, file_num, prefix = 'Progress:', suffix = 'Complete', length = 50)
for x in range(file_num):
    filename = path+r"\%s"% (file_lst[x])
    lst = [0 for _ in range(256)]
    try:
        ole = olefile.OleFileIO(filename)
        stream = ole.openstream('BodyText/Section0')
        stream = BytesIO(zlib.decompress(stream.read(), -15))
        byte = stream.read(1)
        while byte :
            lst[check(byte)] += 1
            byte = stream.read(1)
        for index in range(256):
            total_lst[index] += lst[index] 
    except:
        except_cnt += 1

    
    


    printProgressBar(x+1, file_num, prefix = 'Progress:', suffix = 'Complete', length = 50)
                

for index in range(256):
        result_lst[index] = float(total_lst[index] / file_num) 
print("파일 %d개 기준"% file_num)
for x in range(256):
    print("헥사 값 %02X의 평균 개수: %.4f입니다."% (x, result_lst[x]))
print(file_num,"갯수중 예외파일 갯수는",except_cnt,"개 입니다!")

