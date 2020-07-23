Maximum = 121296*30
#FileHeader 0x00 : 234개
#Section0 0x00 : 121296개 
#Section1 0x00 : 11071개
#DocInfo 0x00 : 18000개

def check(byte):
    if len(byte) != 0:
        return ord(byte)
    else:
        return 0

ole_filesig = 'D0CF11E0A1B11AE1'        
def check_ole_filesig(byte, cmp_str):
    if byte == 208: cmp_str = 'D0' # 16진수 변환
    elif byte == 207: cmp_str += 'CF'
    elif byte == 17: cmp_str += '11'
    elif byte == 224: cmp_str += 'E0'
    elif byte == 161: cmp_str += 'A1'
    elif byte == 177: cmp_str += 'B1'
    elif byte == 26: cmp_str += '1A'
    elif byte == 225: cmp_str += 'E1'
    else: cmp_str = '' # 속도위한 초기화
    return cmp_str

hwp_filesig = '48575020446F63756D656E742046696C65'        
def check_hwp_filesig(byte, cmp_str):
    if byte == 72: cmp_str = '48' # 16진수 변환
    elif byte == 87: cmp_str += '57'
    elif byte == 80: cmp_str += '50'
    elif byte == 32: cmp_str += '20'
    elif byte == 68: cmp_str += '44'
    elif byte == 111: cmp_str += '6F'
    elif byte == 99: cmp_str += '63'
    elif byte == 117: cmp_str += '75'
    elif byte == 109: cmp_str += '6D'
    elif byte == 101: cmp_str += '65'
    elif byte == 110: cmp_str += '6E'
    elif byte == 116: cmp_str += '74'
    elif byte == 32: cmp_str += '20'
    elif byte == 70: cmp_str += '46'
    elif byte == 105: cmp_str += '69'
    elif byte == 108: cmp_str += '6C'
    elif byte == 101: cmp_str += '65'
    else: cmp_str = '' # 속도위한 초기화
    return cmp_str

heapspray = 'F0FF'        
def check_heapspray(byte, cmp_str):
    if byte == 240: cmp_str = 'F0' # 16진수 변환
    elif byte == 255: cmp_str += 'FF'
    else: cmp_str = '' # 속도위한 초기화
    return cmp_str


shell_start = '51555352565790'
def check_shell(byte, cmp_str):
    if byte == 81: cmp_str = '51' # 16진수 변환
    elif byte == 85: cmp_str += '55'
    elif byte == 83: cmp_str += '53'
    elif byte == 82: cmp_str += '52'
    elif byte == 86: cmp_str += '56'
    elif byte == 87: cmp_str += '57'
    elif byte == 144: cmp_str += '90'
    else: cmp_str = '' # 속도위한 초기화
    return cmp_str
