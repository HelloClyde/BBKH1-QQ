#include "paths.h"
#include "h1_filesystem.h"
#include <string.h>
static int migrate(const char *old,const char *next)
{
    h1_file *file=h1_fopen(next,"rb");if(file){h1_fclose(file);return 1;}
    h1_file *source=h1_fopen(old,"rb");if(!source)return 1;file=h1_fopen(next,"wb");if(!file){h1_fclose(source);return 0;}
    unsigned char a[512],b[512];unsigned total=0,n;int ok=1;
    while((n=h1_fread(a,1,sizeof a,source))){if(total>1048576-n||h1_fwrite(a,1,n,file)!=n){ok=0;break;}total+=n;}
    int aclose=h1_fclose(source),bclose=h1_fclose(file);if(aclose||bclose)ok=0;
    if(ok){source=h1_fopen(old,"rb");file=h1_fopen(next,"rb");if(!source||!file)ok=0;
        if(source&&file)for(;;){unsigned x=h1_fread(a,1,sizeof a,source),y=h1_fread(b,1,sizeof b,file);if(x!=y||memcmp(a,b,x)){ok=0;break;}if(!x)break;}
        if(source)h1_fclose(source);if(file)h1_fclose(file);
    }
    if(!ok){h1_remove(next);return 0;}h1_remove(old);return 1;
}
int qq_paths_prepare(void)
{
    (void)h1_mkdir(QQ_APP_DIR);(void)h1_mkdir(QQ_PARENT_DIR);(void)h1_mkdir(QQ_DATA_DIR);(void)h1_mkdir(QQ_AVATAR_DIR);
    return migrate("A:\\H1QQ.ID",H1QQ_IDENTITY_PATH)&&migrate("A:\\H1QQ.LOG",QQ_LOG_PATH)&&migrate("A:\\H1QQ.ERR",QQ_ERROR_PATH)&&migrate("A:\\H1QQ.QR",QQ_QR_PATH)&&migrate("A:\\H1QQ.HAND",QQ_HANDOFF_PATH);
}
