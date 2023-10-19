AES-128
==============
This tool provides encryption/decrytion according to AES(128) standart. The standart is based on symmetric Rijndael algorithm and regulates work with 128/192/256 bit long keys.
My tool works only with 128 bit length key, ie your secret key should be less than 16 symbols. The algorithm has been recognized impregnable even with this key-length.
[Link to the official document for details](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) 

FIXED AND UPGRADED by Mr. JS (October 2023)

## Requirements

Pure Python 3.11 (No third party libraries are used)

## How to install

There is only one file:

```
aes.py
```

Simple put him in your project (no need to install third-party libraries).

## How to use

Now it's simple after my upgrade of this project:

```python
from aes import run, Direction

pwd='1234567890'
data_source = 'This is a text string'
data_encrypted = run(Direction.ENCRYPT, data_source, pwd)
data_decrypted = run(Direction.DECRYPT, data_encrypted, pwd)
print(f'SOURCE:\n{data_source}\nSTORAGE (source=>encrypted):\n{data_encrypted}\nRESULT (source=>encrypted=>decrypted):\n{data_decrypted}')
```
Results:
```
SOURCE:
This is a text string
STORAGE (source=>encrypted):
[228, 65, 17, 225, 113, 34, 220, 249, 40, 93, 247, 195, 208, 93, 228, 140, 64, 231, 122, 38, 98, 186, 82, 229, 87, 122, 167, 242, 46, 67, 27, 86]
RESULT (source=>encrypted=>decrypted):
This is a text string
```
Now it works in Python 3.11 environment

## Notes

If you want to save/load encrypted data in/from file you may use "bytearray" (see example here):

```python
from aes import run, Direction
import os

def decode(filename, pwd=''):
    data = ''
    if os.path.isfile(filename):
        with codecs.open(filename, 'rb') as f:
            data = bytes(f.read())
            data = run(Direction.DECRYPT, data, pwd)
    return data

def encode(filename, data='', pwd=''):
    if os.path.isfile(filename):
        with open(filename, 'wb') as f:
            data = run(Direction.ENCRYPT, data, pwd)
            f.write(bytearray(data))
    return data
```

## Author

Mr. JS
