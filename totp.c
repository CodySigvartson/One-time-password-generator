#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <netinet/in.h>

#define RUN  0
#define TEST  1

/////////////////////
// This code based off TOTP RFC 6238 implementation
// https://tools.ietf.org/html/rfc6238
/////////////////////


int32_t compute_totp(unsigned char seed[], void *timer){
	// swap byte order (credit to Floris from StackOverflow)
	uint64_t t = (uint64_t)timer;
	t = (t & 0x00000000FFFFFFFF) << 32 | (t & 0xFFFFFFFF00000000) >> 32;
	t = (t & 0x0000FFFF0000FFFF) << 16 | (t & 0xFFFF0000FFFF0000) >> 16;
	t = (t & 0x00FF00FF00FF00FF) << 8 | (t & 0xFF00FF00FF00FF00) >> 8;
	printf("time: %llx\n",t);
	char hash[EVP_MAX_MD_SIZE];
	int hash_len;
	//compute hash
	HMAC(EVP_sha512(),seed,strlen((char*)seed),(char*)&t,8,hash,&hash_len);
	// compute the offset
	int offset = hash[hash_len-1] & 0xf;
	int binary = ((hash[offset] & 0x7f) << 24) |
			((hash[offset+1] & 0xff) << 16) |
			((hash[offset+2] & 0xff) << 8) |
			(hash[offset+3] & 0xff);
	// perform modulus
	return binary%100000000;
}

int32_t main (int argc, char *argv[])
{
	int8_t argsok = 0; 
	int8_t mode=0;
	time_t timer;
	unsigned char seed[] = "\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x30\x31\x32\x33\x34";

	if (argc > 1){
		if(strncmp(argv[1], "run", 3)==0){
			mode = RUN; 
			argsok=1;
		}
		else if (strncmp(argv[1], "test", 4)==0){
			argsok=1;
			mode = TEST; 
		}
	}
	if(!argsok){
		perror("'./totp test' or './totp run'\n");
		exit(1);
	}
	if (mode == RUN){

		//compute time segment based on current time/period
		time(&timer);
		unsigned long long t_int = timer;
		timer = timer/30;
		printf("t_int: %llx\n",t_int);
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed, t_int));
	}
	else{
		time(&timer);
		timer = timer/30;
		unsigned long long t_int = 0x0000000000000001;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
		t_int = 0x00000000023523EC; 
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
		t_int = 0x00000000023523ED;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
		t_int = 0x000000000273EF07;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
		t_int = 0x0000000003F940AA;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
		t_int = 0x0000000027BC86AA;
		printf("Time: %llx, OTP: %d\n", t_int, compute_totp(seed,t_int));
	}

	return 0;
}
