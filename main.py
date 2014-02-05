if __name__ == '__main__':

    import os

    import aes128
    
    print('Step 1:')
    while True:
        print('Press 1 for encription smt and 2 for decription')
        way = input()
        if way not in ['1', '2']:
            print('Action denied')
            continue
        else:
            break
    print()

    print('Step 2:')
    while True:
        print('Enter full name of file')
        input_path = input()
        
        if os.path.isfile(input_path):
            break
        else:
            print('This is not a file')
            continue
    print()

    print('Step 3:')
    while True:
        print('Enter your Key for encription/decription. The Key must be less than 16 symbols. Please, don\'t forget it!')
        key = input()
        
        if len(key) > 16:
            print('Too long Key. Imagine another')
            continue
        
        for symbol in key:
            if ord(symbol) > 0xff:
                print('That key won\'t work. Try another using only latin alphabet and numbers')
                continue
        
        break
    print()

    # Input data
    with open(input_path, 'rb') as f:
        data = f.read()    

    if way == '1':
        crypted_data = []
        temp = []
        for byte in data:
            temp.append(byte)
            if len(temp) == 16:
                crypted_part = aes128.encrypt(temp, key)
                crypted_data.extend(crypted_part)
                del temp[:]  

        out_path = os.path.join(os.path.dirname(input_path) , 'crypted_' + os.path.basename(input_path))

        # Ounput data
        with open(out_path, 'xb') as ff:
            ff.write(bytes(crypted_data))

    else: # if way == '2'
        decrypted_data = []
        temp = []
        for byte in data:
            temp.append(byte)
            if len(temp) == 16:
                decrypted_part = aes128.decrypt(temp, key)
                decrypted_data.extend(decrypted_part)
                del temp[:]  

        out_path = os.path.join(os.path.dirname(input_path) , 'decrypted_' + os.path.basename(input_path))

        # Ounput data
        with open(out_path, 'xb') as ff:
            ff.write(bytes(decrypted_data))
    
print('New file here:', out_path)
