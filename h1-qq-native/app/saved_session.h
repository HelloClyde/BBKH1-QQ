#ifndef H1QQ_SAVED_SESSION_H
#define H1QQ_SAVED_SESSION_H
#include "qq_session.h"
#include "identity.h"
/* A valid D2/TGT session is restored locally; expired credentials require QR.
 * No passwords, QR credentials or raw account structs are written. */
int qq_saved_session_load(const h1qq_identity *,qq_account *);
int qq_saved_session_save(h1qq_identity *,const qq_account *);
void qq_saved_session_forget(void);
#endif
