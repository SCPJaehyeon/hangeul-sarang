# HWP5.0 백신 개요

import os # 파일 관리 위한
import sys # 인자 위한
import shutil # 파일 복사 위한

import zlib # zlib 디컴프레스 위한
from io import BytesIO # 바이트 io 위한
import olefile # OLE 파서 이용

from hangeulsarang_cmp import *

path = sys.argv[1] # 첫번째 인자를 대상 폴더 경로 지정
hex_lst = []
hex_lst_hwp = []
hex_lst_section = []
total_lst = [0 for _ in range(256)]

def hangeulsarang(filename):
    x = 0 # index위치
    x_inhwp = 0 # hwp에서 index 위치
    hex_lst = [] # 헥스 리스트
    hex_lst_hwp = []
    sector_size = 0
    cmp_str1 = '' # OLE 비교시 사용
    cmp_str2 = '' # HWP 비교시 사용
    try:
        with open(path+"\\"+filename, "rb") as f:
                            # 헥스 로드
                            byte = f.read(1)
                            while byte:
                                hex_lst.append(check(byte))
                                byte = f.read(1)  # 바이트가 끝날 때 까지 읽기
    except:  # 예외처리
        print(" \"%s\"는 존재하지 않는 파일입니다. 다시 확인해주세요." % filename)
        sys.exit(1)
    hex_lst_len = len(hex_lst) # 길이 저장
    # OLE 파일 판별
    for x in range(hex_lst_len):
        i = hex_lst_len-x
        if i == 0:
            print("End File")
            break
        cmp_str1 = check_ole_filesig(hex_lst[x], cmp_str1)
        if cmp_str1 == ole_filesig:
            print("1. OLE 파일포맷 일치")
            # 리틀 엔디안 판별
            if hex_lst[28]==254 and hex_lst[29]==255:
                print("2. 리틀 엔디안 확인")
                # 섹터 정보 및 루트엔트리 위치 출력
                sector_size = 2**hex_lst[30]
                print("3. 섹터크기 : ", sector_size)
                x = sector_size * (hex_lst[48]+1)
                print("4. Root Entry 절대위치 : ", x)
                ole = olefile.OleFileIO(path+"\\"+filename)
                olelist = ole.listdir(path+"\\"+filename)
                stream_fh = ole.openstream('FileHeader')
                while True:
                    header = stream_fh.read(1)
                    while header:
                        hex_lst_hwp.append(check(header))
                        header = stream_fh.read(1)
                    hex_lst_hwp_len = len(hex_lst)
                    for x_inhwp in range(hex_lst_hwp_len):
                        j = hex_lst_len-x_inhwp
                        if j == 0:
                            print("End FileHeader")
                            break
                        cmp_str2 = check_hwp_filesig(hex_lst_hwp[x_inhwp], cmp_str2) # HWP 파일 판별
                        if cmp_str2 == hwp_filesig:
                            print("5. HWP 파일포맷 일치")
                            print("6. HWP 버전 : ",hex_lst_hwp[35],".",hex_lst_hwp[34],".",hex_lst_hwp[33],".",hex_lst_hwp[32]) # HWP 버전 표시
                            print("7. 악성코드 체킹중...")
                            for check_sec in olelist:
                                if check_sec[0] == 'BodyText' or check_sec[0] == 'DocInfo' or check_sec[0] == 'BinData' or check_sec[0] == 'Scripts':
                                    if check_sec[0] == 'DocInfo':
                                        print("-", check_sec[0], "Checking...")
                                        stream = ole.openstream('DocInfo')
                                        stream = BytesIO(zlib.decompress(stream.read(), -15))
                                        if check_entropy(stream,1) == True:
                                            stream = ole.openstream('DocInfo')
                                            stream = BytesIO(zlib.decompress(stream.read(), -15))
                                            check_ole_heapspray(stream,1)
                                    elif check_sec[0] == 'BinData':
                                        print("-", check_sec[1], "Checking...")
                                        stream = ole.openstream(check_sec)
                                        stream = BytesIO(zlib.decompress(stream.read(), -15))
                                        if check_entropy(stream,1) == True:
                                            stream = ole.openstream(check_sec)
                                            stream = BytesIO(zlib.decompress(stream.read(), -15))
                                            check_ole_heapspray(stream,1)
                                    else:
                                        print("-", check_sec[1], "Checking...")
                                        stream = ole.openstream(check_sec)
                                        stream = BytesIO(zlib.decompress(stream.read(), -15))
                                        if check_entropy(stream,0) == True:
                                            stream = ole.openstream(check_sec)
                                            stream = BytesIO(zlib.decompress(stream.read(), -15))
                                            check_ole_heapspray(stream,0)
                                else:
                                    print("-", check_sec[0], "Checking...")
                                    stream = ole.openstream(check_sec)
                                    if check_entropy(stream,0) == True:
                                        stream = ole.openstream(check_sec)
                                        check_ole_heapspray(stream,0)

                            break
                    break
            else:
                print("지원 형식이 아닙니다.")
                sys.exit(1)

def check_ole_heapspray(stream,isbin):
    hex_lst = []
    cmp_str3 = '' # 힙스프레이 비교시 사용
    cmp_str4 = ''
    tmp_byte = ''
    x = 0
    while True:
        header = stream.read(1)
        while header:
            hex_lst.append(check(header))
            header = stream.read(1)
        hex_lst_len = len(hex_lst)
        for x in range(hex_lst_len):
            i = hex_lst_len-x
            if i == 0:
                print("End Section0")
                break
            cmp_str3 = check_heapspray(hex_lst[x], cmp_str3) # 힙 스프레이 판별
            if cmp_str3 == heapspray and isbin == 0:
                tmpi = i
                print("*Warning* F0 FF발견! Heap Spray가 의심됩니다!!!")
                tmp_byte = format(hex_lst[x+4],'02x')
                tmp_byte += format(hex_lst[x+3],'02x')
                tmp_byte += format(hex_lst[x+2],'02x')
                tmp_byte += format(hex_lst[x+1],'02x')
                tmp_byte = int(tmp_byte,16)
                tmpx = x
                x = tmp_byte
                while x != tmpx:
                    x -= 1
                    cmp_str4 = check_shell(hex_lst[x], cmp_str4)
                    if cmp_str4 == shell_start:
                        print("Shell 함수 형태 발견! 00으로 덮는 중입니다. (덮고난 이후 compress, write는 아직 미구현)")
                        while x != tmp_byte:
                            x += 1
                            hex_lst[x] = 00
                        break
                break
        break

def check_entropy(stream,isbin):
    hex_lst = [0 for _ in range(256)]
    total_lst = [0 for _ in range(256)]
    byte = stream.read(1)
    while byte:
        hex_lst[check(byte)] += 1
        byte = stream.read(1)
    for index in range(256):
        total_lst[index] += hex_lst[index]
    if isbin == 1:
        for x in range(255):
            if total_lst[x] > Maximum:
                print("헥사 값 %02X의 개수 : %d개입니다."% (x, total_lst[x]))
                print("*Warning* 특정 바이트 빈도수가 너무 많습니다! Heap Spray가 의심됩니다!!!")
                return True
    else:
        for x in range(256):
            if total_lst[x] > Maximum:
                print("헥사 값 %02X의 개수 : %d개입니다."% (x, total_lst[x]))
                print("*Warning* 특정 바이트 빈도수가 너무 많습니다! Heap Spray가 의심됩니다!!!")
                return True


def main():
    if len(sys.argv) != 2: # Usage
        print("Usage : python hangeulsarang.py [Folder]")
        print("ex:) python hangeulsarang.py ./hwp5folder")
        sys.exit(1)

    filenames = os.listdir(path)
    print("============한글 5.x 백신 시작============")
    print("폴더내 파일리스트 : ", filenames)
    for filename in filenames:
        print("============",filename,"============")
        hangeulsarang(filename) # 함수 시작
    print("============파일 탐색 완료============")

if __name__ == "__main__": # 메인
    main()
    