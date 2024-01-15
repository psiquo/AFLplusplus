#include <vector>
#include <string>
#include <string.h>
#include <openssl/md5.h>
typedef struct list_s{
    int value;
    struct list_s * next;
} list_t;

list_t *paths = NULL;

FILE *fptr = NULL;
char *filename = NULL;


void append(list_t** l, uint32_t value){
    list_t *block = (list_t *) malloc(sizeof(list_t));
    block->value = value;
    block->next = NULL;

    if(*l == NULL){
        *l = block;
    } else {
        (*l)->next = block;
    }
}

void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
    printf("COLLECTING\n");
    //append(&paths,*guard);

  //  void *PC = __builtin_return_address(0);
  //  char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
  //__sanitizer_symbolize_pc(PC, "%s:%l %f", PcDescr, sizeof(PcDescr));
    //printf(" -- %d %s\n", *guard,PcDescr);
}

int int_len(uint32_t value){
    uint32_t temp = value;
    int i;
    for(i = 0; temp; i++){
        temp /= 10;
    }

    return i + 1;
}
char *list_to_string(list_t *l) {
    int alloc_size = 1;

    for(list_t *head = l; head; head=head->next){
        alloc_size += int_len(head->value);
    }

    char *str = (char *) malloc(alloc_size);

    int offset = 0;
    for(list_t *head = l; head; head=head->next){
        offset += sprintf(str + offset,"%u\n",head->value);
    }
}

void __dump_path_collection(void){
  printf("DUMPING\n");
//   if(filename == NULL) {
//           filename = getenv("AFL_TRACE_FILE");
//   }

//   fptr = fopen(filename,"w");
  
//   MD5_CTX c;
//   ssize_t bytes;  
  
//   unsigned char digest[MD5_DIGEST_LENGTH];

//   const char * path_cstr = list_to_string(paths);

//   MD5_Init(&c);
//   MD5_Update(&c,path_cstr,strlen(path_cstr));
//   MD5_Final(digest,&c);
//   for(int i = 0; i < MD5_DIGEST_LENGTH; i++){
//       fprintf(fptr,"%02x",digest[i]);
//   }
//   fclose(fptr);
}