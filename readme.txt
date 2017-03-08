编译ssp曲线
g++ ssp_pair.cpp ecn.cpp zzn2.cpp zzn.cpp big.cpp cdh.cpp miracl.a
编译aes加密
gcc mraes.c aes.c miracl.a
编译brute
g++ big.cpp brute.cpp -o brute miracl.a
