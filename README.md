AES-128
==============
This tool provides encryption/decrytion according to AES(128) standart. The standart is based on symmetric Rijndael algorithm and regulates work with 128/192/256 bit long keys.
My tool works only with 128 bit length key, ie your secret key should be less than 16 symbols. The algorithm has been recognized impregnable even with this key-length.
[Link to the official document for details](http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf) 


## How to use

The tool is able to encrypt anything which consist of bytes, type of file doesn't matter.
The first way is to put *aes128.py* in project directoty or somewhere in PYTHON PATH and import

```python
import aes128

cipher = aes128.encrypt(input_bytes, key)
message = aes128.decrypt(cipher, key)
```

Input and output types is described in doc strings. I assume you won't use not the English alphabet for the secret key, because ```ord()``` of symbols should return less than 255, ie we can keep it using just 1 byte per symbol.

The second way is to run *main.py* which provides a shy CLI-interface. Just run it and follow the instructions.

## Author

If you want give me feedback - feel free to contact
