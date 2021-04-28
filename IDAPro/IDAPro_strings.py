import idc
import idautils
import idaapi
 
 
decrypt_strings_func = 0x4071d0
decrypt_strings2_func = 0x407250
key1 = [0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x19,0x00,0x00,0x00,0x5c,0x00,0x00,0x00,0xda,0x00,0x00,0x00]
key2 = [0xab,0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x57,0x00,0x00,0x00,0x7a,0x00,0x00,0x00,0x8c,0x00,0x00,0x00,0x40,0x00,0x00,0x00]

 
def ROL(data, shift, size):
	shift %= size
	remains = data >> (size - shift)
	body = (data << shift) - (remains << size)
	return (body + remains)
 
 
def ROR(data, shift, size):
    shift %= size
    body = data >> shift
    remains = (data << (size - shift)) - (body << size)
    return (body + remains)
 
 
def find_function_arg(addr):
    arg = 0
    while arg <= 3:
        addr = idc.prev_head(addr)
        if arg == 1:
            key_len = (get_operand_value(addr, 0))
        elif arg == 2:
            addr_encrypted_buff = (get_operand_value(addr, 0))
        elif arg == 3:
            encrypted_buff_len = (get_operand_value(addr, 0))
        arg += 1
    return key_len,addr_encrypted_buff,encrypted_buff_len
 
 
def get_string(addr, len):
	i = 0
	string = ""
	while i < len:
		string += chr(get_db_byte(addr))
		i += 1
		addr += 1
	return string
 
 
def decrypt_strings1(key_buffer, key_len, encrypted_buffer, string_len):
    i = 0
    result = ""
    while i < string_len:
        a = key_buffer[4*(i%key_len)] 
        encrypted_byte = ord(get_bytes(encrypted_buffer+i,1,0))
        if int(a) <= 0:
            result += chr(ROL(encrypted_byte,a,8))
        else:
            result += chr(ROR(encrypted_byte,a,8))
        i+=1
    return result
 
 
def decrypt_strings2(key_buffer, key_len, encrypted_buffer, string_len):
    i = 0
    result = ""
    while i < string_len:
        a = key_buffer[4*(i%key_len)] 
        encrypted_bytes = get_bytes(encrypted_buffer+i*2,2,0)
        encrypted_bytes = int.from_bytes(encrypted_bytes, byteorder='little')
        if int(a) <= 0:
            result += chr(ROL(encrypted_bytes,a,16))
        else:
            result += chr(ROR(encrypted_bytes,a,16))
        i+=1
    return result
 
 
print ("[+]Decrypting strings 1...\n")
i = 0
for x in XrefsTo(decrypt_strings_func, flags=0):
	key_size,addr_encrypted_string,encrypted_string_len = find_function_arg(x.frm)
	if i < 2:
		#usage of the second half of decrypted key to decrypt first two strings
		decrypted = decrypt_strings1(key1,key_size,addr_encrypted_string,encrypted_string_len)
		i += 1
	else:
		#usage of the full decrypted key
		decrypted = decrypt_strings1(key2,key_size,addr_encrypted_string,encrypted_string_len)
	idaapi.set_cmt(x.frm, decrypted,0)
	idaapi.set_name(addr_encrypted_string,decrypted,1)
	print (decrypted)
	

print ("[+]Decrypting strings 2...\n")
for x in XrefsTo(decrypt_strings2_func, flags=0):
    key_size,addr_encrypted_buff,encrypted_buff_len = find_function_arg(x.frm)
    decrypted = decrypt_strings2(key2,key_size,addr_encrypted_buff,encrypted_buff_len)
    idaapi.set_cmt(x.frm, decrypted,0)
    idaapi.set_name(addr_encrypted_string,decrypted,1)
    print (decrypted)
