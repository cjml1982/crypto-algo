/* test vectors from p1ovect1.txt */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include <memory.h>
#include <stdlib.h>
#include <time.h>

#include "e_os.h"

#include <openssl/crypto.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include<sys/time.h>

#include<unistd.h>

#include <openssl/interface_crypfun.h>
#include <pthread.h>
//#define  MAXWATCHTHREAD	256
#define  MAXWATCHTHREAD	  20

size_t repeat_num, thread_num;
static unsigned int s_thread_para[128][9];//线程参数
pthread_mutex_t s_mutex[4096];//线程锁
size_t test_type;
const char message[] = "Hello World!";
unsigned int msglen = 12;
unsigned char digest[32];
unsigned char sig[100];
unsigned int siglen;
EC_KEY * ec_key_tmp;

static double Time_F2(int s)
{
	double ret = 0;
	static double tmstart;
	struct timeval t_start;
	//get start time
	gettimeofday(&t_start, NULL);
	double start = (((double)t_start.tv_sec)*1000+(double)t_start.tv_usec/1000)/1000;
	if (s == 0)
		 tmstart = start;
	 else {
		 ret = (start - tmstart);
		  printf("Time_F2:%.2f\n",ret);
	 }
	
	return ret;
}


void print_hex(unsigned char *in, int len)
{
	int i;
	for (i=0; i<len; i++)
		printf("%02x", in[i]);
	printf("\n");
}

void * task_neldtv (unsigned int thread_para[])
{
		//临时变量
		int pool_index; //线程池索引
		size_t iRepeat;
		unsigned int rv;
		size_t i;
		
			//线程脱离创建者
#ifdef UNIX
			pthread_detach(pthread_self());
#endif
	
		pool_index = thread_para[7];
	
		pthread_mutex_lock(s_mutex + pool_index);//等待线程解锁
	
		if (test_type==1)
			{
				for ( i = 0; i < repeat_num; i++ ) { // 根据函数指针确定需要调用的具体函数				
				rv = ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
				
				if ( rv!=1 )
				{	
					thread_para[8]++;
				}
				else
					thread_para[5]++;
				}
			}
		if (test_type==2)
			{
				for ( i = 0; i < repeat_num; i++ ) { // 根据函数指针确定需要调用的具体函数

				
				rv = ECDSA_verify(0, digest, 32, sig, siglen, ec_key_tmp);
				
				if ( rv!=1 )
				{	
					thread_para[8]++;
				}
				else
					thread_para[5]++;
				}
			}	
	
		//线程结束
		thread_para[0] = 0;//设置线程占用标志为"空闲"

		pthread_exit(NULL);

}

int init_thread_pool_neldtv()
{
		size_t i;
		pthread_t	tid;
	
		size_t thCnt = thread_num<MAXWATCHTHREAD?thread_num:MAXWATCHTHREAD;
	
		//初始化线程池参数
		for(i = 0; i < thread_num; i++) {
			s_thread_para[i][0] = 1;//设置线程占用标志为"使用"
			s_thread_para[i][1] = 0;
			s_thread_para[i][2] = 0;
			s_thread_para[i][3] = 0;
			s_thread_para[i][4] = 0;
			s_thread_para[i][5] = 0;
			s_thread_para[i][6] = 0;
			s_thread_para[i][7] = i;//线程池索引
			s_thread_para[i][8] = 0;

			pthread_mutex_lock(s_mutex + i);//线程锁
		}
	
		//创建线程池
		for(i = 0; i < thCnt; i++) {
			s_thread_para[i][1] = test_type;
			int rc = pthread_create(&tid, 0, (void *)task_neldtv, (void *)(s_thread_para[i]));
			if (0 != rc) {
				fprintf(stderr, "pthred_create() failed(%d)\r\n", (int)i);
				return(-1);
			}

		}
	
		return 0;
}


 int test_ecdsa_speed(int times, int pthreadnum, int opendev)
{
	int rc;
		size_t i;
		int active_num = 0;
		int connect_err = 0;
		int send_err = 0;
		int recv_err = 0;
		int close_num = 0;
		float	finish_num = 0;
		int cmp_num = 0;
		int 	yewu_err = 0;
	
		double	t1;
	

		test_type = opendev;
		thread_num = pthreadnum;
		repeat_num = times;
	
		//线程池初始化
		rc = init_thread_pool_neldtv();
		
		if ( 0 != rc ) 
			return rc;
	
		//线程解锁
		for(i = 0; i < pthreadnum; i++) {
			pthread_mutex_unlock(s_mutex + i);
		}
		
		
		//统计输出
	
		Time_F2(0);

		for( ; ; ) {
			active_num = 0;
			connect_err = 0;
			send_err = 0;
			recv_err = 0;
			close_num = 0;
			finish_num = 0;
			cmp_num = 0;
			yewu_err = 0;
	
			for(i = 0; i < thread_num; i++) {
				active_num += s_thread_para[i][0];
				connect_err += s_thread_para[i][1];
				send_err += s_thread_para[i][2];
				recv_err += s_thread_para[i][3];
				close_num += s_thread_para[i][4];
				finish_num += s_thread_para[i][5];
				cmp_num += s_thread_para[i][6];
				yewu_err += s_thread_para[i][8];
			}
			
			if (0 == active_num) break;
		}
		t1 = Time_F2(1);//stop
		printf("finsh num:%.2f\n",finish_num);
		fprintf(stdout, "Total time is %.2f;\r\nAverage is %.2f/sec\r\n", t1, (finish_num / t1));
	
		return 0;

}



int main(int argc, char *argv[])
{
	int times, pthreadnum,signorverify,timess,isopen;
	int rv;
	EVP_Digest(message, msglen, digest, NULL, EVP_sha256(), NULL);
	//ec_key_tmp = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	ec_key_tmp = EC_KEY_new_by_curve_name(NID_secp256k1);
	if (ec_key_tmp == NULL)
	{
		printf("\nEC key generate failed!\n");
		goto err;
	}
	EC_KEY_generate_key(ec_key_tmp);
       printf( "\nPlease Select software or hardware to compute(0 is software,1 is hardware)" );
	scanf( "%d", &isopen);
	if(isopen){
		rv = NELDTV_open_cryptodev();
		if (rv)
			{
				printf("NELDTV_open_cryptodev Failed!!! Error: %#x\r\n", rv);
				return rv;
			}
		else
			{
				printf("NELDTV cryptodev version: %s\n", NELDTV_get_version_cryptodev());
			}
	}
	rv = ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
	if(rv!=1){
		printf("\ninit  failed!\n");
		goto err;
	}
	printf("\n##########ECDSA TEST START###########\n");
	printf( "\nUsing %s to TEST",isopen?"NELDTV hardware ":"openssl software" );
	printf( "\nPlease Select repeat number(10000):" );
	scanf( "%d", &times );
	timess = times;
	printf( "\nPlease Select thread_num(2-20):" );
	scanf( "%d", &pthreadnum);
	printf( "\nPlease Select test function(sign is 1,verify is 2):" );
	scanf( "%d", &signorverify);	
	test_ecdsa_speed(times, pthreadnum, signorverify);
       printf("\n##ECDSA TEST USING ONE BY ONE##\n");
	int i =0;double t;
	if(signorverify == 1){
		Time_F2(0);
		for( i =0;i<times;i++){
			 ECDSA_sign(0, digest, 32, sig, &siglen, ec_key_tmp);
		}
		t= Time_F2(1);

	}else{
		Time_F2(0);
		for( i =0;i<times;i++){
			 ECDSA_verify(0, digest, 32, sig, siglen, ec_key_tmp);
		}
		t= Time_F2(1);
	}	
	printf("ECDSA speed in one fock, %.2f/sec\n", timess /t);

	printf("\n##########ECDSA TEST END###########\n");
	EC_KEY_free(ec_key_tmp);

err:
	return rv;
}

