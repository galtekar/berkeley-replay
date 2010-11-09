#ifndef LWRAP_SIGS
#define LWARP_SIGS

#define LOG_AND_DELIVER_QUEUED_SIGNALS() \
	if (_private_info.num_pending_sigs) { \
		log_and_deliver_queued_signals(); \
	}

extern void install_signal_handlers();
extern void log_and_deliver_queued_signals();

#endif
