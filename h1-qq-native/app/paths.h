#ifndef H1QQ_PATHS_H
#define H1QQ_PATHS_H
/* Native filesystem paths are GBK. Only the client preincludes this header. */
#define QQ_APP_DIR "A:\\" "\xd3\xa6\xd3\xc3"
#define QQ_PARENT_DIR QQ_APP_DIR "\\" "\xca\xfd\xbe\xdd"
#define QQ_DATA_DIR QQ_PARENT_DIR "\\QQ"
#define QQ_AVATAR_DIR QQ_DATA_DIR "\\AVATAR"
#define H1QQ_IDENTITY_PATH QQ_DATA_DIR "\\H1QQ.ID"
#define QQ_LOG_PATH QQ_DATA_DIR "\\H1QQ.LOG"
#define QQ_ERROR_PATH QQ_DATA_DIR "\\H1QQ.ERR"
#define QQ_QR_PATH QQ_DATA_DIR "\\H1QQ.QR"
#define QQ_HANDOFF_PATH QQ_DATA_DIR "\\H1QQ.HAND"
#define QQ_SESSION_PATH QQ_DATA_DIR "\\H1QQ.SES"
#ifndef __ASSEMBLER__
int qq_paths_prepare(void);
#endif
#endif
