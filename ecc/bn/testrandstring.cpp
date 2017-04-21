#include<iostream>
#include<ctime>
#include"stdlib.h"
using namespace std;
const int LEN_NAME=4;
char *rand_str(char *str,int min,int max)
{
	int i,len = rand() % (min - max + 1) + min;
	for(i=0;i<len;++i)
		str[i]='A'+rand()%26;
	str[i]='\0';
	return str;
}
 
int main()
{
	srand((unsigned)time(NULL));
	int i,min = 10,max = 50;
	char name[max+1];
        for(i=0;i<20;++i)
	{
		cout<<rand_str(name,min,max)<<endl;
        }
	return 0;
}
