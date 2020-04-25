
def openObj_r(path):
    """
    Opens object file to be loaded
    """
    return (open(path, 'rb'))

def openObj_w(path):
    """
    Opens object file to be closed
    """
    return (open(path, 'wb'))

def byte2int(value, sign=False):
    return int.from_bytes(value, byteorder='little', signed=sign)
