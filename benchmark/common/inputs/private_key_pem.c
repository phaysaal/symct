/* 
 * index = der_to_arr(DER-index) = 29+(DER-index/64)*65+(DER-index % 64)
 * length should be calculated based on indices
 *   length = toArr(DER-index + DER-length) - toArr(DER-index) 
 */

const char PRIVATE_KEY_PEM[] =
  /*  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIIEpAIBAAKCAQEAw16xupRgGt9gHXqpm8bZj0ksXp7lX/WXbyB95UcZ4zQad9lX\n"
"nq2jmwRMiWzjULD1Z1T9MOFis4MddRm6ONvIR/McBGne65ayNmXBOa3O93dWl+Ip\n"
"gK3ce/SBQjJJgAwKTQa0uu8znr7g9fjifCCA7xAXFr25JobKcOBP6xA4txiSod1q\n"
"bZHj+iawE464YGLqotKIHYIlc7O7oHylaz9wfQKxtLsPZYTfRYHUm66DU3by/0Y7\n"
"FOAWk/rhwNN0860s7TCFfRKzgUC9nhfFNyQuRHKY7Mho8HbpX18Bz+T2TZM6vRAi\n"
"UMxVCb8SQPbdxa+bS8D83omeffpTw39lE8qgSQIDAQABAoIBAAylATSB1CcFGE3M\n"
"IbRV9kCAdEVS/CY96U1NUWygkY+7kG97kwDPfPBkYrY9xIgVTerATMtIORjEdoh8\n"
"z+lMaz3h4Yk1F3MQu6vK4erDYarxT7rQjc5Y4lVo9aE0yz5E+TkzQwj6wJDoinuM\n"
"/k6ZlXKzjEUB5jz0uh88W1vLvtn1uWwXcsulDAiOUUBImGH/rwrb0bLBm1uOjFvC\n"
"VScxicQOo0rQcIsTzxt8PMMf3rIX1enCT1IJrqHD7/+cUlvlLuXl4SVl+yTVHZgy\n"
"9QBLZARTwNeuXbIGTS+l0leRwTWlRLlitg1tovNkgE7Y/NyLASHsOqVUq1XKfzCq\n"
"+bQS4wECgYEA+oa+Fz1e2HYwrPq1rCyNxfOwnfmguVl4UANKJ/R41YPWDTAUn6dc\n"
"ghMGgb5CKbDVkiElsdSQdvSljw4i0FCAZI5BFK8aOfcHw4SZZGtQxTCerbPee2TS\n"
"24SkS8i+8G7zno/5WrLV7nZJ/hL15S+NgOAoZkPJUF5GooHpvfGAlwECgYEAx6Ny\n"
"nt/Y5StTIK/qjELL4kyoZyyqk3dXe48nQSF71iMqAuCZ1MCLBFh2IiUQMzjXtj+E\n"
"j5j8f3q5aYJN58qALp0Rfivd10YVAp7nUIIMn2Ak/peqNXbRnct1kX9gN75KPzLd\n"
"QDYiYERpSkQmqitcDiheqq8Kl1nbFvsYj7iYkUkCgYEAliCyvyh2ss64wqAGyGN2\n"
"nf43g6N4zjmwYHpoMONOmdzEI+kBIt9fD0+pYYyLB4LBqS0V8qgH3lEi+UQmVqE3\n"
"H4sjsupvk/bV/zNx3Hx2zYQiQsN7+oPj28pzzjpBOcGzWfy7F7/9dUYLdycTlcDW\n"
"UjmB3C6Y8AFe4LlrQfj77wECgYBjKzsl1pZciJ/7jcdaM1gqKuBAmDyHknHfi+X5\n"
"AZQNdFxLH5zqxVaJKxRLs9OPTj5BZt4HovxSqvjtg3AFo173SMjGvy2s4UBQk/Td\n"
"1ixFAzJ9UYOYmVRZKRdW1kpKhnlFWZP0cK+02GbhIGeAgpdw5PbZnKgLNPSTPtod\n"
"kpofGQKBgQDpGItGxePda7vMVJYJtOu9X/S/9gPKBxhiudEhtgxBlP8Ze/iY9EiN\n"
"oOmQCkBQAJsDhSDWPqAJFSI4foFCjLq6dwuNs+pzr+RDiPMV6OL+7fkWQPK3A33w\n"
"0cQzugWO19I0MBSh4C5FFN6WfV9x0dV0I2r+VBTwB1fT8M9BgNXOGg==\n"
"-----END RSA PRIVATE KEY-----\n";
  */
  "-----BEGIN PRIVATE KEY-----\n" //29
  "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDDXrG6lGAa32Ad\n" //29+65= 94   64
  "eqmbxtmPSSxenuVf9ZdvIH3lRxnjNBp32VeeraObBEyJbONQsPVnVP0w4WKzgx11\n" //94+65=159  128
  "Gbo428hH8xwEad7rlrI2ZcE5rc73d1aX4imArdx79IFCMkmADApNBrS67zOevuD1\n" //159+65=224 
  "+OJ8IIDvEBcWvbkmhspw4E/rEDi3GJKh3WptkeP6JrATjrhgYuqi0ogdgiVzs7ug\n" //224+65=289 256
  "fKVrP3B9ArG0uw9lhN9FgdSbroNTdvL/RjsU4BaT+uHA03TzrSztMIV9ErOBQL2e\n" //289+65=354 320
  "F8U3JC5EcpjsyGjwdulfXwHP5PZNkzq9ECJQzFUJvxJA9t3Fr5tLwPzeiZ59+lPD\n" //354+65=419 384
  "f2UTyqBJAgMBAAECggEADKUBNIHUJwUYTcwhtFX2QIB0RVL8Jj3pTU1RbKCRj7uQ\n" //419+65=484     392-384=8 8+419=427
  "b3uTAM988GRitj3EiBVN6sBMy0g5GMR2iHzP6UxrPeHhiTUXcxC7q8rh6sNhqvFP\n" //484+             
"utCNzljiVWj1oTTLPkT5OTNDCPrAkOiKe4z+TpmVcrOMRQHmPPS6HzxbW8u+2fW5\n"
"bBdyy6UMCI5RQEiYYf+vCtvRssGbW46MW8JVJzGJxA6jStBwixPPG3w8wx/eshfV\n"
"6cJPUgmuocPv/5xSW+Uu5eXhJWX7JNUdmDL1AEtkBFPA165dsgZNL6XSV5HBNaVE\n"
"uWK2DW2i82SATtj83IsBIew6pVSrVcp/MKr5tBLjAQKBgQD6hr4XPV7YdjCs+rWs\n"
"LI3F87Cd+aC5WXhQA0on9HjVg9YNMBSfp1yCEwaBvkIpsNWSISWx1JB29KWPDiLQ\n"
"UIBkjkEUrxo59wfDhJlka1DFMJ6ts957ZNLbhKRLyL7wbvOej/lastXudkn+EvXl\n"
"L42A4ChmQ8lQXkaigem98YCXAQKBgQDHo3Ke39jlK1Mgr+qMQsviTKhnLKqTd1d7\n"
"jydBIXvWIyoC4JnUwIsEWHYiJRAzONe2P4SPmPx/erlpgk3nyoAunRF+K93XRhUC\n"
"nudQggyfYCT+l6o1dtGdy3WRf2A3vko/Mt1ANiJgRGlKRCaqK1wOKF6qrwqXWdsW\n"
"+xiPuJiRSQKBgQCWILK/KHayzrjCoAbIY3ad/jeDo3jOObBgemgw406Z3MQj6QEi\n"
"318PT6lhjIsHgsGpLRXyqAfeUSL5RCZWoTcfiyOy6m+T9tX/M3HcfHbNhCJCw3v6\n"
"g+PbynPOOkE5wbNZ/LsXv/11Rgt3JxOVwNZSOYHcLpjwAV7guWtB+PvvAQKBgGMr\n"
"OyXWllyIn/uNx1ozWCoq4ECYPIeScd+L5fkBlA10XEsfnOrFVokrFEuz049OPkFm\n"
"3gei/FKq+O2DcAWjXvdIyMa/LazhQFCT9N3WLEUDMn1Rg5iZVFkpF1bWSkqGeUVZ\n"
"k/Rwr7TYZuEgZ4CCl3Dk9tmcqAs09JM+2h2Smh8ZAoGBAOkYi0bF491ru8xUlgm0\n"
"671f9L/2A8oHGGK50SG2DEGU/xl7+Jj0SI2g6ZAKQFAAmwOFINY+oAkVIjh+gUKM\n"
"urp3C42z6nOv5EOI8xXo4v7t+RZA8rcDffDRxDO6BY7X0jQwFKHgLkUU3pZ9X3HR\n"
"1XQjav5UFPAHV9Pwz0GA1c4a\n"
"-----END PRIVATE KEY-----\n"
;
const int PRIVATE_KEY_PEM_len = sizeof(PRIVATE_KEY_PEM) - 1;
#define KEY_PREFIX_LEN 29 
#define der_to_idx(x) (KEY_PREFIX_LEN + (x/64)*65 + (x%64))
const int skip = 22;
const int Nidx = der_to_idx(skip + 7);
const int Eidx = der_to_idx(skip + 268);
const int Didx = der_to_idx(skip + 273);
const int Pidx = der_to_idx(skip + 533);
const int Qidx = der_to_idx(skip + 665);
const int DPidx = der_to_idx(skip + 797);
const int DQidx = der_to_idx(skip + 929);
const int Qinvidx = der_to_idx(skip + 1060);

