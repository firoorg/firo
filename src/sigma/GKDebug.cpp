//
//  debug.cpp
//  sigma
//
//  Created by David Gray on 24/01/2018.
//  Copyright © 2018 formal. All rights reserved.
//

#include "GKDebug.hpp"

#ifdef DEBUG
void debugBuffer(const unsigned char* data,size_t length) {
    size_t next = 0;
    while (next < length) {
        fprintf(stderr,"%05zx:",next);
        for (size_t i = 0; i < WIDTH; i++) {
            if (next+i < length) {
                fprintf(stderr," %02x",data[next+i]);
            } else {
                fprintf(stderr,"   ");
            }
        }
        fprintf(stderr," ");
        for (size_t i = 0; i < WIDTH; i++) {
            if (next+i < length) {
                unsigned char ch = data[next+i];
                if ((ch >= 32) && (ch <= 127)) {
                    fprintf(stderr,"%c",ch);
                } else {
                    fprintf(stderr,".");
                }
            } else {
                fprintf(stderr," ");
            }
        }
        fprintf(stderr,"\n");
        next += WIDTH;
    }
}
#else
void debugBuffer(const unsigned char* data,size_t length) {
}
#endif
