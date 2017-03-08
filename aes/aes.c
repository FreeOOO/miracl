#include "mirdef.h"
#include "miracl.h"
#include <malloc.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

#define NUM 2
#define MODE MR_CFB2
#define _NK 16

void encrypt_(aes *_aes,char *szAesKey,char *iv,char *szStr,long int sizetemp,int size){
	//加密
	struct timeval start,end;
	aes_init(_aes,MODE,_NK,szAesKey,iv);
	int len;
	gettimeofday(&start,NULL);
	for(long int i = 0;i < size;i++){
		len = aes_encrypt(_aes,&szStr[i * NUM]);
	}
	gettimeofday(&end,NULL);
	int timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	aes_end(_aes);
 //	printf("密文八进制表示:");
 //	for(int i = 0;i < sizetemp;i++){
 //		printf("%-4o",(unsigned char)szStr[i]);
 //	}
 //	printf("\n");
	printf("encrypt time:%d us\n",timeuse);			//输出微秒
}

void decrypt_(aes *_aes,char *szAesKey,char *iv,char *szStr,int sizearr,int size){
	//解密
	struct timeval start,end;
	aes_init(_aes,MODE,_NK,szAesKey,iv);
	gettimeofday(&start,NULL);
	int len;
	for(long int i = 0;i < size;i++){
		len = aes_decrypt(_aes,&szStr[i * NUM]);
	}
	gettimeofday(&end,NULL);
	int timeuse = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
	aes_end(_aes);
//	for(long int i = 0;i < sizearr;i++){
//		printf("%-4o",(unsigned char)szStr[i]);
//	}
//	printf("\n");
	printf("decrypt time:%d us\n",timeuse);			//输出微秒
}

void AesTest(char *szStr1,char *miwen,char *mingwen)
{
	aes _aes;
	char szAesKey[] = "1234567890abcdef";		//加密密钥
//	char szStr1[] = {"eradsfasdfasdfasfsdda"};	//明文
	char iv[17] = "1213112342321432";			//用于生产密钥流
	long int size = strlen(szStr1);
	printf("%ld\n",size);
	long int sizearr = size;		//数组实际长度
	long int sizetemp = (sizearr % NUM == 0 ? sizearr : (sizearr / NUM + 1 ) * NUM);		//加密后数组长度
	char *szStr = (char *)malloc((sizetemp + 1) * sizeof(char));
	strcpy(szStr,szStr1);		//拷贝到新数组
	size = size % NUM != 0 ? size / NUM + 1 : size / NUM;		//密文分组长度
//	printf("密钥:%s\n",szAesKey);
//	printf("明文:%s\n",szStr);
//	printf("明文八进制表示:");
//	for(int i = 0;i < sizearr;i++){
//		printf("%-4o",(unsigned char)szStr[i]);
//	}
 //	printf("\n");
	encrypt_(&_aes,szAesKey,iv,szStr,sizetemp,size);
	strcpy(miwen,szStr);
	decrypt_(&_aes,szAesKey,iv,szStr,sizearr,size);
	strcpy(mingwen,szStr);
 //	printf("解密后明文:%s\n",szStr);
//	return szStr;
	free(szStr);
}
int main(){
	FILE *outfpencrypt,*infp,*outfpdecrypt;
	infp = fopen("./a.txt","rb");
	outfpencrypt = fopen("./a.encrypt","wb");
	outfpdecrypt = fopen("./a.decrypt","wb");
	fseek(infp,0,SEEK_END);
	long lSize = ftell(infp);
	rewind(infp);

	char *buff,*miwen,*mingwen;
	buff = (char *)malloc(sizeof(char) * lSize);
	miwen = (char *)malloc(sizeof(char) * lSize);
	mingwen = (char *)malloc(sizeof(char) * lSize);

	size_t result = fread(buff,1,lSize,infp);
	AesTest(buff,miwen,mingwen);
	fputs(miwen,outfpencrypt);
	fputs(mingwen,outfpdecrypt);

/*	char buff[500002],miwen[500002],mingwen[500002];
	int rc;
	while((rc=fread(buff,sizeof(unsigned char),500000,infp)) != 0){
		AesTest(buff,miwen,mingwen);
		fwrite(miwen,sizeof(unsigned char),rc,outfpencrypt);
		fwrite(mingwen,sizeof(unsigned char),rc,outfpmingwen);
	}*/
/*	while(!feof(infp)){
		if(fgets(buff,10000,(FILE*)infp) != NULL){
			AesTest(buff,miwen,mingwen);
			fputs(miwen,outfpencrypt);
			fputs(mingwen,outfpmingwen);
		}
	}*/
	/*char buff[255000];
	fp = fopen("./a.txt","r");
	while(!feof(fp)){
		if(fgets(buff,255000,(FILE*)fp) != NULL){
			if(buff[strlen(buff) - 1] == '\n') //去除回车符
				buff[strlen(buff) - 1] = '\0';
			AesTest(buff);
		}
	}*/
	free(buff);
	free(miwen);
	free(mingwen);
	fclose(outfpdecrypt);
	fclose(outfpencrypt);
	fclose(infp);
}
