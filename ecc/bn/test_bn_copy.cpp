#include <iostream>
#include <ctime>
#include <sstream>
#include <stack>
#include "big.h"
#include "ecn2.h"
#include "stdlib.h"
#include <unistd.h>

#define MIN 500
#define MAX 1000

//#define MR_PAIRING_SS2    // AES-80 or AES-128 security GF(2^m) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128

//#define MR_PAIRING_SSP    // AES-80 or AES-128 security GF(p) curve
//#define AES_SECURITY 80   // OR
//#define AES_SECURITY 128

#define MR_PAIRING_BN    // AES-128 or AES-192 security
#define AES_SECURITY 128

//#define MR_PAIRING_MNT
//#define AES_SECURITY 80

//#define MR_PAIRING_CP      // AES-80 security
//#define AES_SECURITY 80

//#define MR_PAIRING_KSS    // AES-192 security
//#define AES_SECURITY 192

//#define MR_PAIRING_BLS    // AES-256 security
//#define AES_SECURITY 256

//#include "pairing_1.h"
#include "pairing_3.h"

using namespace std;

PFC pfc(AES_SECURITY);  //global pfc

Big hash256(char *str){
	//miracl *mip=mirsys(33,16);	//先初始化miracl,之后使用Big
	miracl *mip = get_mip();	//当其他地方初始化miracl后，需要这一行获取
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
		a *= 256;
		a += (unsigned char)hash[i];
	}
	return a;
}

void set(){	
	clock_t start,end;
	G1 a,b,s,a1,b1,b2;
	//G2 A,B,S;
	GT V;
	Big x,wi;
	char smg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	pfc.random(x);
	pfc.random(a);
	pfc.random(b);
	pfc.precomp_for_mult(a);		//预计算a
	pfc.precomp_for_mult(b);
	start = clock();
	wi = hash256(smg);
	//char t[] = "123456";
	//pfc.hash_and_map(A,t);
	//pfc.hash_and_map(B,t);
	//cout << x << endl;
	//A = pfc.mult(A,x);
	//B = pfc.mult(B,x);
	//B = pfc.mult(B,wi);
	//S = A + B;
	a1 = pfc.mult(a,x);
	b1 = pfc.mult(b,x);
	b1 = pfc.mult(b1,wi);
	s = a + b1;
	end = clock();
	cout << "set time:" << (double)(end-start)*1000/CLOCKS_PER_SEC << endl;
	//V = pfc.pairing(R,P);
	//pfc.precomp_for_power(V);
	//cout << V.g << endl;
}

void cerVer(int num = 70){
	clock_t start,end;
	G1 a,b,c,d,aa,aa1;
	G2 e,f;
	GT P,Q;
	Big x;
	pfc.random(e);
	pfc.random(aa);
	pfc.random(x);
	pfc.precomp_for_mult(e);
	start = clock();
	for(int i = 0;i < num;i++)		//计算每一个hi
		pfc.hash_and_map(a,(char *)"121asdfadfjkh389724yjklhasfhafaas45af3asdfq32r489hajkfhaks");
	pfc.random(a);
	b = a;
	for(int i = 1;i < num;i++)		//所有hi相加
		b = b + a;
	f = pfc.mult(e,x);			//计算第二个pairing中的G2,pkca
	Q = pfc.pairing(f,b);			//计算第二个pairing
	aa1 = aa;
	for(int i = 1;i < num;i++){		//计算第一个pairing中的G1
		aa1 = aa1 + aa;
	}
	P = pfc.pairing(e,aa1);		//计算第一个pairing
	end = clock();
	cout << num <<"  Certificate Verification time:" << (double)(end-start)*1000/CLOCKS_PER_SEC << endl;
}

void medSigVer(int num = 70){
	clock_t start,end;
	G1 a,b,c,s,a1,b1,g1,m,n;
	G2 g2,e,f,g21,g22;
	GT P,Q,R,X;
	Big x,w;
	pfc.random(a);
	pfc.random(b);
	pfc.random(x);
	pfc.random(w);
	pfc.random(g1);
	pfc.random(e);
	pfc.random(f);
	pfc.random(g2);
	pfc.random(g21);
	pfc.random(g22);
	pfc.precomp_for_mult(a);
	pfc.precomp_for_mult(b);
	a1 = pfc.mult(a,x);
	b1 = pfc.mult(b,x);
	b1 = pfc.mult(b1,w);
	c = a1 + b1;
	start = clock();
	s = c;					//计算消息签名si
	for(int i = 1;i < num;i++)		//计算si相加
		s = s + c;
	m = pfc.mult(g1,x);			//计算vpki
	for(int i = 1;i < num;i++)		//计算第二个pairing中的G1
		m = m + m;
	n = pfc.mult(g1,x);
	n = pfc.mult(n,w);
	for(int i = 1;i < num;i++)		//计算第三个pairing中的G1
		n = n + n;
	P = pfc.pairing(g2,s);			//计算第一个pairing
	//Q = pfc.pairing(g21,m);			//计算第二个pairing
	//R = pfc.pairing(g22,n);			//计算第三个pairing
	//X = Q * R;				//后两个pairing相乘
	G1 *arr1[2];
	G2 *arr2[2];
	arr1[0] = &m;
	arr1[1] = &n;
	arr2[0] = &g21;
	arr2[1] = &g22;
	X = pfc.multi_pairing(2,arr2,arr1);
	end = clock();
	cout << num << "  Message signature verification time:" << (double)(end-start)*1000/CLOCKS_PER_SEC << endl;
}

char *rand_str(char *str,int min,int max)
{
	//srand((unsigned)time(NULL));
	//cout << clock() << endl;
	//cout << time(NULL) << endl;
	int i,len = rand() % (min - max + 1) + min;
        for(i=0;i<len;++i)
		str[i]='A'+rand()%26;
	str[i]='\0';
        return str;
}

double batVer(int num = 70){
	clock_t start,end;
	G1 si1,si2,s1,s2,pi0,pi1,Pi0,Pi1,Pi;
	G2 Pcs,p2,u2;
	Big ci;
	pfc.random(si1);
	pfc.random(si2);
	pfc.random(p2);
	pfc.random(u2);
	pfc.precomp_for_pairing(p2);
	pfc.precomp_for_pairing(u2);
	s1 = si1;
	s2 = si2;
	start = clock();
	for(int i = 1;i < num;i++){
		s1 = s1 + si1;
		s2 = s2 + si2;
	}
	pfc.hash_and_map(Pcs,(char *)"asdfasdfasdfdfasdfa");
	for(int i = 0;i < num;i++){
		pfc.hash_and_map(pi0,(char *)"ioa8ysdf872qy34rj");
		pfc.hash_and_map(pi1,(char *)"ioasfsdaf8ysdf872qy34rj");
		ci = pfc.hash_to_group((char *)"asdfq9823475ulhkajsdf");
	}
	pfc.pairing(p2,s1);
	Pi0 = pi0;
	Pi1 = pi1;
	for(int i = 1;i < num;i++){
		Pi0 = Pi0 + pi0;
		Pi1 = pfc.mult(pi1,ci);
	}
	Pi = Pi0 + Pi1;
	G1 *arr1[2] = {&s2,&Pi};
	G2 *arr2[2] = {&Pcs,&u2};
	pfc.multi_pairing(2,arr2,arr1);
	end = clock();
	return (double)(end-start)*1000/CLOCKS_PER_SEC;
}

int main(int argc,char* argv[]){
	srand((unsigned)time(NULL));
	//int array[] = {50,100,200};
	//int length = sizeof(array) / sizeof(array[0]);
	//int array[argc - 1];
	//for(int i = 1;i < argc;i++){
	//	array[i - 1] = atoi(argv[i]);
	//}
	//int num;
	//for(int i = 0;i < argc - 1;i++){
	//	set();
	//	cerVer(array[i]);
	//	medSigVer(array[i]);
	//	batVer(array[i]);
	//}
	cout << "格式为./test_bn.out a b c,从[a,b],求c次平均值" << endl;
	for(int i = atoi(argv[1]);i <= atoi(argv[2]);i++){
		set();
		double time = 0;
		for(int j = 0;j < atoi(argv[3]);j++){
			usleep(1000 * 80);
			time += batVer(i);
		}
		cout << i << ":" << time / atoi(argv[3]) << endl;
	}
	return 0;
}
