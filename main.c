#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "DES.h"
#define BLOCK_MODE 4	/* 1: CBC, 2: CFB, 3: OFB, 4: CTR */
#define NONCE 661F98CD37A38B4B

// CBC
void DES_CBC_Enc(BYTE*, BYTE*, BYTE*, BYTE*, int);
void DES_CBC_Dec(BYTE*, BYTE*, BYTE*, BYTE*, int);
// CFB
void DES_CFB_Enc(BYTE*, BYTE*, BYTE*, BYTE*, int);
void DES_CFB_Dec(BYTE*, BYTE*, BYTE*, BYTE*, int);
// OFB
void DES_OFB_Enc(BYTE*, BYTE*, BYTE*, BYTE*, int);
void DES_OFB_Dec(BYTE*, BYTE*, BYTE*, BYTE*, int);
//CTR
void DES_CTR_Enc(BYTE*, BYTE*, BYTE*, UINT64, int);
void DES_CTR_Dec(BYTE*, BYTE*, BYTE*, UINT64, int);

int main()
{
    int i;
    BYTE p_text[128]={0,};
    BYTE key[9]={0,};
    BYTE IV[9]={0,};
    BYTE c_text[128]={0,};
    BYTE d_text[128]={0,};
    int msg_len;
    UINT64 ctr=0;

    /* 평문 입력 */
    printf("평문 입력: ");
	gets((char *)p_text);
    /* 비밀키 입력 */
    printf("비밀키 입력: ");
	scanf("%s", key);
    fflush(stdin);

    #if(BLOCK_MODE!=4)
    /* 초기화 벡터 입력 */
    printf("초기화 벡터 입력: ");
	scanf("%s", IV);
    #else
    /* 카운터 입력 */
    printf("ctr 입력: ");
	scanf("%u", &ctr);
    #endif

/* 메시지 길이 계산 */
    msg_len=(strlen((char *)p_text) % BLOCK_SIZE) ?
                  ((strlen((char *)p_text) / BLOCK_SIZE +1)*8):
                  strlen((char *)p_text);
    #if(BLOCK_MODE==1)
    DES_CBC_Enc(p_text, c_text, IV, key, msg_len);//DES-CBC 암호화
    #elif(BLOCK_MODE==2)
    DES_CFB_Enc(p_text, c_text, IV, key, msg_len);//DES-CFB 암호화
    #elif(BLOCK_MODE==3)
    DES_OFB_Enc(p_text, c_text, IV, key, msg_len);//DES-OFB 암호화
    #else
    DES_CTR_Enc(p_text, c_text, key, ctr, msg_len);//DES-CTR 암호화
    #endif
	
    /* 암호문 출력 */
    printf("\n암호문: ");
    for(i=0; i<msg_len; i++)
        printf("%c", c_text[i]);
    printf("\n");

	

    #if(BLOCK_MODE==1)
    DES_CBC_Dec(c_text, d_text, IV, key, msg_len);//DES-CBC 복호화
    #elif(BLOCK_MODE==2)
    DES_CFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB 복호화
    #elif(BLOCK_MODE==3)
    DES_OFB_Dec(c_text, d_text, IV, key, msg_len);//DES-CFB 복호화
    #else
    DES_CTR_Dec(c_text, d_text, key, ctr, msg_len);//DES-CTR 복호화
    #endif

    /* 복호문 출력 */
    printf("\n복호문: ");
    for(i=0; i<msg_len; i++)
        printf("%c", d_text[i]);
    printf("\n");

    return 0;
}

// CBC
void DES_CBC_Enc(BYTE* p_text, BYTE* c_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE* chain = IV;
	BYTE input_text[128] = {0,};
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		for(j=0; j<BLOCK_SIZE; j++) {
			input_text[i*BLOCK_SIZE+j] = p_text[i*BLOCK_SIZE+j] ^ chain[j];
		}
		
		DES_Encryption(input_text+(i*BLOCK_SIZE), c_text+(i*BLOCK_SIZE), key);
		chain = c_text+(i*BLOCK_SIZE);
	}
}

void DES_CBC_Dec(BYTE* c_text, BYTE* d_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE* chain = IV;
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		DES_Decryption(c_text+(i*BLOCK_SIZE), d_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<BLOCK_SIZE; j++) {
			d_text[i*BLOCK_SIZE+j] = d_text[i*BLOCK_SIZE+j] ^ chain[j];
		}
		
		chain = c_text+(i*BLOCK_SIZE);
	}
}

// CFB
void DES_CFB_Enc(BYTE* p_text, BYTE* c_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE* chain = IV;
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		DES_Encryption(chain, c_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<BLOCK_SIZE; j++) {
			c_text[i*BLOCK_SIZE+j] = c_text[i*BLOCK_SIZE+j] ^ p_text[i*BLOCK_SIZE+j];
		}
		
		chain = c_text+(i*BLOCK_SIZE);
	}
}

void DES_CFB_Dec(BYTE* c_text, BYTE* d_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE* chain = IV;
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		DES_Encryption(chain, d_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<BLOCK_SIZE; j++) {
			d_text[i*BLOCK_SIZE+j] = d_text[i*BLOCK_SIZE+j] ^ c_text[i*BLOCK_SIZE+j];
		}
		
		chain = c_text+(i*BLOCK_SIZE);
	}
}

// OFB
void DES_OFB_Enc(BYTE* p_text, BYTE* c_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE chain[9] = {0,};
	
	for(j=0; j<9; j++) chain[i] = IV[i];
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		DES_Encryption(chain, c_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<9; j++) chain[i] = c_text[i*BLOCK_SIZE+j];
		
		for(j=0; j<BLOCK_SIZE; j++) {
			c_text[i*BLOCK_SIZE+j] = c_text[i*BLOCK_SIZE+j] ^ p_text[i*BLOCK_SIZE+j];
		}
	}
}

void DES_OFB_Dec(BYTE* c_text, BYTE* d_text, BYTE* IV, BYTE* key, int msg_len) {
	int i, j;
	BYTE chain[9] = {0,};
	
	for(j=0; j<9; j++) chain[i] = IV[i];
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		DES_Encryption(chain, d_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<9; j++) chain[i] = d_text[i*BLOCK_SIZE+j];
		
		for(j=0; j<BLOCK_SIZE; j++) {
			d_text[i*BLOCK_SIZE+j] = d_text[i*BLOCK_SIZE+j] ^ c_text[i*BLOCK_SIZE+j];
		}
	}
}

//CTR
void DES_CTR_Enc(BYTE* p_text, BYTE* c_text, BYTE* key, UINT64 ctr, int msg_len) {
	int i, j;
	BYTE chain[8] = {0,};
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		for(j=7; j>=0 && ctr>0; j--) {
			chain[j] = ctr%256;
			ctr/=256;
		}

		DES_Encryption(chain, c_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<BLOCK_SIZE; j++) {
			c_text[i*BLOCK_SIZE+j] = c_text[i*BLOCK_SIZE+j] ^ p_text[i*BLOCK_SIZE+j];
		}
		
		ctr++;
	}
}

void DES_CTR_Dec(BYTE* c_text, BYTE* d_text, BYTE* key, UINT64 ctr, int msg_len) {
	int i, j;
	BYTE chain[8] = {0,};
	
	for(i=0; i<msg_len/BLOCK_SIZE; i++) {
		for(j=7; j>=0 && ctr>0; j--) {
			chain[j] = ctr%256;
			ctr/=256;
		}
		
		DES_Encryption(chain, d_text+(i*BLOCK_SIZE), key);
		
		for(j=0; j<BLOCK_SIZE; j++) {
			d_text[i*BLOCK_SIZE+j] = d_text[i*BLOCK_SIZE+j] ^ c_text[i*BLOCK_SIZE+j];
		}
		
		ctr++;
	}
}

