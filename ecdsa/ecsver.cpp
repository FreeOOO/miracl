/*
 *   Elliptic Curve Digital Signature Algorithm (ECDSA)
 *
 *
 *   This program verifies the signature given to a <file> in
 *   <file>.ecs generated by program ecsign
 * 
 *   The curve is y^2=x^3+Ax+B mod p
 *
 *   The file common.ecs is presumed to exist, and to contain the domain
 *   information {p,A,B,q,x,y}, where A and B are curve parameters, (x,y) are
 *   a point of order q, p is the prime modulus, and q is the order of the 
 *   point (x,y). In fact normally q is the prime number of points counted
 *   on the curve. 
 *
 *   Requires: big.cpp ecn.cpp
 *
 */

#include <iostream>
#include <fstream>
#include <cstring>
#include "ecn.h"
#include <ctime>
#include <unistd.h>

using namespace std;

#ifndef MR_NOFULLWIDTH
Miracl precision(200,256);
#else
Miracl precision(50,MAXBASE);
#endif

void strip(char *name)
{ /* strip off filename extension */
    int i;
    for (i=0;name[i]!='\0';i++)
    {
        if (name[i]!='.') continue;
        name[i]='\0';
        break;
    }
}

static Big Hash(ifstream &fp)
{ /* compute hash function */
    char ch,s[20];
    Big h;
    sha sh;
    shs_init(&sh);
    forever 
    { /* read in bytes from message file */
        fp.get(ch);
        if (fp.eof()) break;
        shs_process(&sh,ch);
    }
    shs_hash(&sh,s);
    h=from_binary(20,s);
    return h;
}

double ecdsaver()
{
clock_t start,end;
    ifstream common("common.ecs");    /* construct file I/O streams */
    ifstream public_key("public.ecs");
    ifstream message;
    ifstream signature;
    ECn G,Pub;
    int bits,ep;
    Big a,b,p,q,x,y,v,u1,u2,r,s,h;
    char ifname[50],ofname[50];
    miracl *mip=&precision;

/* get public data */
    common >> bits;
    mip->IOBASE=16;
    common >> p >> a >> b >> q >> x >> y;
    mip->IOBASE=10;
    ecurve(a,b,p,MR_PROJECTIVE);
    G=ECn(x,y);
/* get public key of signer */
    public_key >> ep >> x;

    //mip->IOBASE = 2;
    //cout << x << endl;

    //cout << MAXBASE << endl;
    Pub=ECn(x,ep);         // decompress
/* get message */
    //cout << "signed file = " ;
    //cin.sync();
    //cin.getline(ifname,13);
    strcpy(ifname,"111.txt");
    strcpy(ofname,ifname);
    strip(ofname);
    strcat(ofname,".ecs");
    message.open(ifname,ios::binary|ios::in); 
    if (!message)
    { /* no message */
        cout << "Unable to open file " << ifname << "\n";
        return 0;
    }
start = clock();
    h=Hash(message);

    signature.open(ofname,ios::in);
    if (!signature)
    { /* no signature */
        cout << "signature file " << ofname << " does not exist\n";
        return 0;
    }
    signature >> r >> s;

    mip->IOBASE = 2;
    cout << r << endl;

    if (r>=q || s>=q)
    {
        cout << "Signature is NOT verified\n";
        return 0;
    }
    s=inverse(s,q);
    u1=(h*s)%q;
    u2=(r*s)%q;

    G=mul(u2,Pub,u1,G);
    G.get(v);
    v%=q;
end = clock();
//cout << "time:" << (double)(end-start)*1000/CLOCKS_PER_SEC << endl;
    if (v==r) cout << "Signature is verified\n";
    else      cout << "Signature is NOT verified\n";
    cout << start << "  " << end << endl;
    return (double)(end-start)*1000/CLOCKS_PER_SEC;
}

int main(int argc,char* argv[]){
	double time = 0;
	double temp = 0;
	for(int i = 0;i < atoi(argv[1]);i++){
		temp = ecdsaver();
		usleep(1000 * 100);		//睡眠防止连续运行时寄存器之类缓存数据，使运行时间递减
		cout << temp << endl;
		time += temp;
	}
	cout << "time:" << time / atoi(argv[1]) << endl;
}
