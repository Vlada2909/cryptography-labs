import os
import Aes

# key for example 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

input_path = os.path.abspath(input("Enter the path to file with a plaintext: "))
key = input("Key :")
with open(input_path, 'rb') as f:
    data = f.read()
crypted_data = []
temp = []
for byte in data:
    temp.append(byte)
    if len(temp) == 16:
        crypted_part = Aes.encrypt(temp, key)
        crypted_data.extend(crypted_part)
        del temp[:]
else:
    if 0 < len(temp) < 16:
        empty_spaces = 16 - len(temp)
        for i in range(empty_spaces - 1):
            temp.append(0)
        temp.append(1)
        crypted_part = Aes.encrypt(temp, key)
        crypted_data.extend(crypted_part)

out_path = os.path.join(os.path.dirname(input_path), 'crypted_' + os.path.basename(input_path))
with open(out_path, 'xb') as ff:
    ff.write(bytes(crypted_data))
decrypted_data = []
temp = []
for byte in crypted_data:
    temp.append(byte)
    if len(temp) == 16:
        decrypted_part = Aes.decrypt(temp, key)
        decrypted_data.extend(decrypted_part)
        del temp[:]
else:
    if 0 < len(temp) < 16:
        empty_spaces = 16 - len(temp)
        for i in range(empty_spaces - 1):
            temp.append(0)
        temp.append(1)
        decrypted_part = Aes.decrypt(temp, key)
        decrypted_data.extend(crypted_part)

out_path = os.path.join(os.path.dirname(input_path), 'decrypted_' + os.path.basename(input_path))
with open(out_path, 'xb') as g:
    g.write(bytes(decrypted_data))


