AES-128
==============
That tool provides encryptin/secrpting according to AES(128) standart. Standart is based on symmetric Rijndael algorithm and regulates work with 128/192/256 bit length of a key.
My tool works only with 128 bit length key, ie your secret key should be less than 16 symbols. The algorithm has been recognized impregnable even with this key-length.
Link to an official document for detailes: 
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf

How to use
==========
The tool is able to crypt anything which consist of bytes, type of file doesn't matter.
The first way is to put *aes128.py* in project directoty or somewhere in PYTHON PATH and import
```python
import aes128

cipher = aes128.encrypt(input_bytes, key)
message = aes128.decrypt(cipher, key)
```
Input and output types is described in doc strings. I assume you won't use not english alphabet for the secret key, because ```python ord()``` of symbols should return less than 255, ie we can keep it using just 1 byte.

The second way is to run *main.py* which provides a shy CLI-interface. Just run it and follow the instructions.

Author
======
If you want smth to say - feel free to contact me
