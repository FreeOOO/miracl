#include <iostream>
#include <ctime>
#include <sstream>
#include <stack>
#include "big.h"
#include "ecn2.h"

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
		pfc.hash_and_map(a,(char *)"121asdf3q4523gdfsasdfsdfd:asfdj;l82u7riojhshajkaksj983289jkajkhsfkjhfiuqawef98235h;;;.,zxc/,v;lakfa09809-2384;lkjasadfjkh389724yjklhasfhafaas45af3asdfq32r489hajkfhaks");
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

void batVer(int num = 70){
	clock_t start,end;
	//G1 hi;
	//G2 g2,pkca;
   	//Big x,ri;	   
	G1 a,b,c,s,a1,b1,g1,m,n,hi,hI,aa,aa1;
	G2 g2,e,f,g21,g22,pkca;
	GT P,Q,R,S,X;
	Big x,w,ri,xi;
	pfc.random(a);
	pfc.random(b);
	pfc.random(aa);
	pfc.random(x);
	pfc.random(w);
	pfc.random(ri);
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
	for(int i = 1;i < num;i++)		//计算第三个pairing中的G1
		m = m + m;
	n = pfc.mult(g1,x);			//计算vpki
	n = pfc.mult(n,w);			//vpki的w次方
	aa1 = aa;
	for(int i = 1;i < num;i++){	
		n = n + n;			//计算第四个pairing中的G1
		aa1 = aa1 + aa;			//计算第一个pairing中的σ
	}
	aa1 = pfc.mult(aa1,ri);			//计算第一个pairing中的G1
	P = pfc.pairing(g2,s + aa);		//计算第一个pairing
	//Q = pfc.pairing(g21,m);			//计算第三个pairing
	//R = pfc.pairing(g22,n);			//计算第四个pairing
	for(int i = 0;i < num;i++)		//计算第二个pairing中的hi
		pfc.hash_and_map(hi,(char *)"123234123414");
	hI = hi;
	for(int i = 1;i < num;i++)		//计算hi相加
		hI = hI + hi;
	hI = pfc.mult(hI,ri);			//计算第二个pairing中的G1
	pkca = pfc.mult(g2,xi);			//计算第二个pairing中的paca
	//S = pfc.pairing(pkca,hI);		//计算第二个pairing
	//X = Q * R * S;				//后三个pairing相乘
	G1 *arr1[3];
	G2 *arr2[3];
	arr1[0] = &hI;
	arr1[1] = &m;
	arr1[2] = &n;
	arr2[0] = &pkca;
	arr2[1] = &g21;
	arr2[2] = &g22;
	X = pfc.multi_pairing(3,arr2,arr1);
	end = clock();
	cout << num << "  batch verification time:" << (double)(end-start)*1000/CLOCKS_PER_SEC << endl;
}

int main(int argc,char* argv[]){
	int array[argc - 1];
	for(int i = 1;i < argc;i++){
		array[i - 1] = atoi(argv[i]);
	}
	//int array[] = {50,100,200};
	//int length = sizeof(array) / sizeof(array[0]);
	int num;
	for(int i = 0;i < argc - 1;i++){
		set();
		cerVer(array[i]);
		medSigVer(array[i]);
		batVer(array[i]);
	}
	return 0;
}
