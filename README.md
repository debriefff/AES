AES-128
==============
This tool provides encryption/decrytion according to AES(128) standart. The standart is based on symmetric Rijndael algorithm and regulates work with 128/192/256 bit long keys.
My tool works only with 128 bit length key, ie your secret key should be less than 16 symbols. The algorithm has been recognized impregnable even with this key-length.
[Link to the official document for details](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) 


## How to use

Now it's simple after my upgrade of this project:

```python
from aes import run, Direction

pwd='1234567890'
data_source = 'This is a text string #!\nЭто новая текстовая строка №!'
print(f'SOURCE:\n{data_source}')
data_encrypted = run(Direction.ENCRYPT, data_source, pwd)
print(f'STORAGE(source=>encrypted):\n{data_encrypted}')
data_decrypted = run(Direction.DECRYPT, data_encrypted, pwd)
print(f'RESULT (source=>encrypted=>decrypted):\n{data_decrypted}')
```
Now it works in Python 3.11 environment

## Author

Mr. JS
