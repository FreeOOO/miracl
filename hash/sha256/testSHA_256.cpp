#include <iostream>
#include <ctime>
#include <string>
#include "big.h"

using namespace std;

Big hash256(char *str){
	miracl *mip=mirsys(33,16);	//先初始化miracl,之后使用Big
	mip->IOBASE = 16;		//设置进制为16
	Big a = 1;
	sha256 sh;
	char hash[32];
	shs256_init(&sh);			//初始化sha256
	for(int i = 0;str[i] != 0;i++){
		shs256_process(&sh,str[i]);	//每次输入一个字节
	}
	shs256_hash(&sh,hash);			//将哈希值存在hash中
	a = (unsigned char)hash[0];
	for(int i = 1;i < 32;i++){
		//printf("%x",(unsigned char)hash[i]);
		a *= 256;
		a += (unsigned char)hash[i];
	}
	return a;
}

int main(){
	char test[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	cout << hash256(test) << endl;
	return 0;
}
