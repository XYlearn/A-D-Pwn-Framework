from pwn import *

binary = "{binary}"
dbg_script = '''
'''

def get_flag(io):
    return ""

def pwn_remote(ip, port, *args, **kargs):
    '''pwn remote gamebox [ip]:[port], return flag and io'''
    io = remote(ip, port)
    flag = get_flag(io)
    if not kargs.get('keep_alive'):
        io.close()
    return flag, io

def pwn_local(io, debug=False):
    get_flag(io)

if __name__ == '__main__':
    pass
