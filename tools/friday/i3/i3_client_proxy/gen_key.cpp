#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <string>
#include <set>
#include <algorithm>
#include <map>
#include <stdlib.h>

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

int main(int argc,char* argv[])
{
  CRYPTO_malloc_debug_init();
  CRYPTO_dbg_set_options(V_CRYPTO_MDEBUG_ALL);
  CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
  RAND_seed(rnd_seed, sizeof rnd_seed);
  char file1[] = "public.key";
  char file2[] = "private.key";
  char file3[] = "pub.key";

  RSA* myprivatekey = RSA_generate_key(1024,17,NULL,NULL);

  if (argc < 2)
  {
    printf("Please specify username\n");
    exit(-1);
  }

  FILE* fp1 = fopen( (argc>=3)? argv[2]: file1,"a");
  FILE* fp2 = fopen( (argc>=4)? argv[3]: file2,"w");
  FILE* fp3 = fopen( (argc>=5)? argv[4]: file3,"w");

  fprintf(fp1,"%s ",argv[1]);
  fprintf(fp2,"%s ",argv[1]);
  fprintf(fp3,"%s ",argv[1]);
  
  fprintf(fp1,"%s ",BN_bn2dec((myprivatekey->n)));
  fprintf(fp1,"%s\n",BN_bn2dec((myprivatekey->e)));

  fprintf(fp3,"%s ",BN_bn2dec((myprivatekey->n)));
  fprintf(fp3,"%s\n",BN_bn2dec((myprivatekey->e)));
 
  fprintf(fp2,"%s ",BN_bn2dec((myprivatekey->n)));
  fprintf(fp2,"%s ",BN_bn2dec((myprivatekey->e)));
  fprintf(fp2,"%s ",BN_bn2dec((myprivatekey->d)));
  fprintf(fp2,"%s ",BN_bn2dec((myprivatekey->p)));
  fprintf(fp2,"%s\n",BN_bn2dec((myprivatekey->q)));

  fclose(fp1);
  fclose(fp2);
  fclose(fp3);

  RSA_free(myprivatekey);

  printf("Please upload pub.key to the i3 -> IP proxy you wish to use\n");
  printf("Your private key is stored in private.key\n");
   
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0);  
  // CRYPTO_mem_leaks_fp(stderr);

  return 0;
}
