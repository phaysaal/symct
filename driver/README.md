
```
driver <LIBRARY> <ALGORITHM> <TEST-TYPE> <ROOT-PATH> [--tag <TAG> | --platform <PLATFORM> | --bn | --debug | --timeout <TIMEOUT> | --progressive <STUB-FILES> | --keylen 1024 ]*
```

## Rules:

- `<ROOT-PATH>/benchmark/<PLATFORM>/<LIBRARY>/<ALGORITHM>` must exist.
- `<ROOT-PATH>/binsec/<PLATFORM>/<LIBRARY>/<TEST-TYPE>.ini` must exist if `<TEST-TYPE>` is not 'dry'.
- `<ROOT-PATH>/binsec/<PLATFORM>/<LIBRARY>/`...??


- `<LIBRARY>` can be openssl. 

- `<ALGORITHM>` can be rsa_decrypt, rsa_decrype_oaep, sign.

- `<TEST-TYPE>` will be either 'dry', 'rsa_full', 'rsa_1byte', etc. Rules:

- `<ROOT-PATH>` is the path under which we will have 'benchmark' and 'binsec' folders. 

- `<STUB-FILES>` is a comma separated ordered-list of files must exist in 'binsec/<PLATFORM>/<LIBRARY>/progressive' folder. 

## Example:

With all default configuration
```
driver openssl rsa_decrypt rsa_full .. 
```

30 min analysis for 32-bit program
```
driver openssl rsa_decrypt rsa_full .. --tag e_bin2bn --platform 32 --bn --debug --timeout 1800
```

For progressive analysis
```
driver openssl rsa_decrypt rsa_full .. --tag e_bin2bn --platform 32 --bn --keylen 1024 --debug --timeout 300 --progressive BN_bin2bn.ini,BN_div.ini
```

