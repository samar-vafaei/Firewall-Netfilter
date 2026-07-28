#ifndef LOGGER_H
#define LOGGER_H

#include <linux/in.h>
#include <linux/kernel.h>
#include "packet_parser.h"

const char* protocol_name(u8 protocol);
void logger(struct packet_info *pkt);

#endif
