#!/usr/bin/env python3
import argon2
import sys

def get_keyed_hash(data, salt, iterations, mem_usage):
    #hash_full = argon2.low_level.hash_secret(data, salt=salt, time_cost=iterations, memory_cost=mem_usage, parallelism=8,hash_len=32,type=argon2.low_level.Type.ID).decode(encoding='utf8')
    hash_raw = argon2.low_level.hash_secret_raw(data, salt=salt, time_cost=iterations, memory_cost=mem_usage, parallelism=8,hash_len=32,type=argon2.low_level.Type.ID).hex()
    return hash_raw

def get_keyed_hash_fast(data, salt):
    return get_keyed_hash(data, salt, 400, 2**14)

def get_keyed_hash_slow(data, salt):
    return get_keyed_hash(data, salt, 4000, 2**14)

def get_pin(prefix_data, salt):
    data = []
    data.extend(prefix_data)
    msg = 'PIN'
    data.extend(msg.encode(encoding='utf8'))
    data = bytes(data)
    
    hash_hexval = get_keyed_hash_fast(data, salt)
    hash_intval = int(hash_hexval, 16)
    return str(hash_intval)[8:14]

def get_admin_pin(prefix_data, salt):
    data = []
    data.extend(prefix_data)
    msg = 'ADMIN PIN'
    data.extend(msg.encode(encoding='utf8'))
    data = bytes(data)
    
    hash_hexval = get_keyed_hash_slow(data, salt)
    hash_intval = int(hash_hexval, 16)
    return str(hash_intval)[8:16]

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('error: usage %s master_key' % (sys.argv[-7]))
        exit(1)
    
    master_key = sys.argv[1]
    master_key_data = []
    try:
        master_key_data = bytes.fromhex(master_key)
    except:
        pass

    if len(master_key_data) != 32:
        print('error: master_key needs to be a string of 64 hexadecimal characters')
        exit(1)

    print('Using master key %s' % (master_key))

    salt = master_key_data[0:16]
    key_data_part = master_key_data[16:32]

    pin_code = get_pin(key_data_part, salt)
    print('PIN: %s' % (pin_code))

    admin_code = get_admin_pin(key_data_part, salt)
    print('ADMIN PIN: %s' % (admin_code))
