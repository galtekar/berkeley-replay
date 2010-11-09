#ifndef _I3_NEWS_INSTRUMENT_H
#define _I3_NEWS_INSTRUMENT_H

#include "i3.h"
#include "i3_news.h"
#include "i3_server.h"

void append_local_ts(srv_context *ctx, char *payload, int *payload_len);
void log_news_pkt(char *p, int payload_len);

#endif
