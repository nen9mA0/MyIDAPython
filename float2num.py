def num2float(num):
    tmp = num & 0xffffffff
    sign = tmp >> 31
    if sign == 1:
        sign = -1
    else:
        sign = 1
    power = ((tmp >> 23) & 0xff) - 127
    ori = 1.0

    mul_num = 0.5
    for i in xrange(23):
        a = (tmp>>(22-i))&1
        if a != 0:
            ori += mul_num
        mul_num = mul_num / 2.0
    ori = sign * (ori * (2**power))
    return ori

def float2num(num):
    if num > 0:
        sign = 0
    else:
        sign = 1

    power = 0
    tmp = num
    while True:
        if tmp < 1.0:
            power -= 1
            tmp *= 2
        elif tmp > 2.0:
            power += 1
            tmp /= 2
        else:
            break
    tmp -= 1.0
    mycmp = 0.5
    tmpnum = 0
    for i in xrange(23):
        tmpnum = tmpnum << 1
        if tmp > mycmp:
            tmpnum |= 1
            tmp -= mycmp
        mycmp /= 2
    ret = (sign<<31) | (((power+127)&0xff)<<23) | tmpnum
    return ret

def num2double(num):
    tmp = num & 0xffffffffffffffff
    sign = tmp >> 63
    if sign == 1:
        sign = -1
    else:
        sign = 1
    power = ((tmp >> 52) & 0x7ff) - 1023
    ori = 1.0

    mul_num = 0.5
    for i in xrange(52):
        a = (tmp>>(51-i))&1
        if a != 0:
            ori += mul_num
        mul_num = mul_num / 2.0
    ori = sign * (ori * (2**power))
    return ori

def double2num(num):
    if num > 0:
        sign = 0
    else:
        sign = 1

    power = 0
    tmp = num
    while True:
        if tmp < 1.0:
            power -= 1
            tmp *= 2
        elif tmp > 2.0:
            power += 1
            tmp /= 2
        else:
            break
    tmp -= 1.0
    mycmp = 0.5
    tmpnum = 0
    for i in xrange(52):
        tmpnum = tmpnum << 1
        if tmp > mycmp:
            tmpnum |= 1
            tmp -= mycmp
        mycmp /= 2
    ret = (sign<<63) | (((power+1023)&0x7ff)<<52) | tmpnum
    return ret

# =======test=======
if __name__ == "__main__":
    print hex(float2num(0.002761415))
    print num2float(float2num(0.1020313))
    print num2float(float2num(1247193913.12831471))
    print num2double(double2num(1247193913.12831471))
    print num2double(0x40C3880000000000)
    print hex(double2num(1.0))