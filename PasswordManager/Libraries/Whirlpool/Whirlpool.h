//
//  Whirlpool.h
//  PasswordManager
//
//  Created by Gints Murans on 25/06/14.
//  Copyright (c) 2014 Early Bird. All rights reserved.
//

#include "nessie.h"

/**
 * Initialize the hashing state.
 */
void NESSIEinit(struct NESSIEstruct * const structpointer);


/**
 * Delivers input data to the hashing algorithm.
 *
 * @param    source        plaintext data to hash.
 * @param    sourceBits    how many bits of plaintext to process.
 *
 * This method maintains the invariant: bufferBits < DIGESTBITS
 */
void NESSIEadd(const unsigned char * const source,
               unsigned long sourceBits,
               struct NESSIEstruct * const structpointer);

/**
 * Get the hash value from the hashing state.
 *
 * This method uses the invariant: bufferBits < DIGESTBITS
 */
void NESSIEfinalize(struct NESSIEstruct * const structpointer,
                    unsigned char * const result);
