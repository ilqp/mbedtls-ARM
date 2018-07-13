/*
 *  AES-GCM file encryption program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_fprintf    fprintf
#define mbedtls_printf     printf
#endif

#include "mbedtls/gcm.h"
#include "mbedtls/aes.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  aescrypt2 <mode> <input filename> <output filename>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: aescrypt2 0 file file.aes\n" \
    "\n"

#if !defined(MBEDTLS_AES_C) || !defined(MBEDTLS_SHA256_C) || \
    !defined(MBEDTLS_FS_IO) || !defined(MBEDTLS_MD_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_AES_C and/or MBEDTLS_SHA256_C "
                    "and/or MBEDTLS_FS_IO and/or MBEDTLS_MD_C "
                    "not defined.\n");
    return( 0 );
}
#else
int main( int argc, char *argv[] )
{
    int ret = 1;

    unsigned int i, n;
    int mode;
    size_t keylen;
    FILE *fkey, *fin = NULL, *fout = NULL;

    unsigned char IV[16];
    unsigned char tmp[16];
    unsigned char key[48];
    unsigned char digest[16];
    unsigned char buffer[1024];
    unsigned char diff;

    mbedtls_gcm_context gcm_ctx;
    mbedtls_entropy_context entropy_ctx;
    mbedtls_ctr_drbg_context ctr_drbg_ctx;

#if defined(_WIN32_WCE)
    long filesize, offset;
#elif defined(_WIN32)
       LARGE_INTEGER li_size;
    __int64 filesize, offset;
#else
      off_t filesize, offset;
#endif

    /*
     * Parse the command-line arguments.
     */
    if( argc != 4 )
    {
        mbedtls_printf( USAGE );

#if defined(_WIN32)
        mbedtls_printf( "\n  Press Enter to exit this program.\n" );
        fflush( stdout ); getchar();
#endif

        goto exit;
    }

    mode = atoi( argv[1] );
    memset( IV,     0, sizeof( IV ) );
    memset( key,    0, sizeof( key ) );
    memset( digest, 0, sizeof( digest ) );
    memset( buffer, 0, sizeof( buffer ) );

    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        mbedtls_fprintf( stderr, "invalide operation mode\n" );
        goto exit;
    }

    if( strcmp( argv[2], argv[3] ) == 0 )
    {
        mbedtls_fprintf( stderr, "input and output filenames must differ\n" );
        goto exit;
    }

    if( ( fin = fopen( argv[2], "rb" ) ) == NULL )
    {
        mbedtls_fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
        goto exit;
    }

    if( ( fout = fopen( argv[3], "wb+" ) ) == NULL )
    {
        mbedtls_fprintf( stderr, "fopen(%s,wb+) failed\n", argv[3] );
        goto exit;
    }

    /*
     * Read the secret key from file or command line
     */

    mbedtls_entropy_init( &entropy_ctx );
    mbedtls_ctr_drbg_init( &ctr_drbg_ctx );
    if( ( fkey = fopen( "aes_key.bin", "rb" ) ) != NULL )
    {
        keylen = fread( key, 1, sizeof( key ), fkey );
        fclose( fkey );
    }
    else
    {
        /*
         * Initialize random number generation
         */
        mbedtls_printf( "  aes_key.bin doesnt exist Create a new key in next step...\n" );
        mbedtls_printf( "  . Seeding the random number generator..." );
        fflush( stdout );

        ret = mbedtls_ctr_drbg_seed( &ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx,
                                     (const unsigned char *) "RANDOM_GEN", 10 );
        if( ret != 0 ) {
            mbedtls_printf("  . mbedtls_ctr_drbg_seed() returned %d", ret);
            goto exit;
        }

        mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg_ctx, MBEDTLS_CTR_DRBG_PR_OFF );
        mbedtls_printf(" ok\n");

        /*
         * Generate random data for AES Key and IV
         */
        mbedtls_printf( "  . Generate random AES Key..." );
        fflush( stdout );

        ret = mbedtls_ctr_drbg_random( &ctr_drbg_ctx, key, sizeof( key ) );
        if( ret != 0 )
        {
            mbedtls_printf("  . mbedtls_ctr_drbg_random() failed, ret = %d\n", ret);
            goto exit;
        }

        if( ( fkey = fopen( "aes_key.bin", "wb" ) ) != NULL )
        {
            keylen = fwrite( key, 1, sizeof( key ), fkey );
            fclose( fkey );
        }
        mbedtls_printf( " ok\n" );
    }

#if defined(_WIN32_WCE)
    filesize = fseek( fin, 0L, SEEK_END );
#else
#if defined(_WIN32)
    /*
     * Support large files (> 2Gb) on Win32
     */
    li_size.QuadPart = 0;
    li_size.LowPart  =
        SetFilePointer( (HANDLE) _get_osfhandle( _fileno( fin ) ),
                        li_size.LowPart, &li_size.HighPart, FILE_END );

    if( li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR )
    {
        mbedtls_fprintf( stderr, "SetFilePointer(0,FILE_END) failed\n" );
        goto exit;
    }

    filesize = li_size.QuadPart;
#else
    if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
    {
        perror( "lseek" );
        goto exit;
    }
#endif
#endif

    if( fseek( fin, 0, SEEK_SET ) < 0 )
    {
        mbedtls_fprintf( stderr, "fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

    mbedtls_gcm_init( &gcm_ctx );
    if( mode == MODE_ENCRYPT )
    {
        memcpy( IV, key + 31, 16 );

        /*
         * Append the IV at the beginning of the output.
         */
        if( fwrite( IV, 1, 16, fout ) != 16 )
        {
            mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            goto exit;
        }

	mbedtls_gcm_setkey( &gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	mbedtls_gcm_starts( &gcm_ctx, MBEDTLS_GCM_ENCRYPT, IV, sizeof(IV), NULL, 0);

        /*
         * Encrypt and write the ciphertext.
         */
        for( offset = 0; offset < filesize; offset += 16 )
        {
            n = ( filesize - offset > 16 ) ? 16 : (int)
                ( filesize - offset );

            if( fread( buffer, 1, n, fin ) != (size_t) n )
            {
                mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", n );
                goto exit;
            }

	    mbedtls_gcm_update( &gcm_ctx, n, buffer, buffer);

            if( fwrite( buffer, 1, n, fout ) != n )
            {
                mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
                goto exit;
            }
        }

        /*
         * Finally write the HMAC.
         */
	mbedtls_gcm_finish( &gcm_ctx, digest, sizeof(digest));

        if( fwrite( digest, 1, 16, fout ) != 16 )
        {
            mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
            goto exit;
        }
    }

    if( mode == MODE_DECRYPT )
    {
        /*
         *  The encrypted file must be structured as follows:
         *
         *        00 .. 15              Initialization Vector
         *        16 .. 31              AES Encrypted Block #1
         *           ..
         *      N*16 .. (N+1)*16 - 1    AES Encrypted Block #N
         *  (N+1)*16 .. (N+1)*16 + 32   HMAC-SHA-256(ciphertext)
         */
        if( filesize < 48 )
        {
            mbedtls_fprintf( stderr, "File too short to be encrypted.\n" );
            goto exit;
        }

        /*
         * Subtract the IV + GCM Digest length.
         */
        filesize -= ( 16 + 16 );

        /*
         * Read the IV and original filesize modulo 16.
         */
        if( fread( IV, 1, 16, fin ) != 16 )
        {
            mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
            goto exit;
        }

	mbedtls_gcm_setkey( &gcm_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
	mbedtls_gcm_starts( &gcm_ctx, MBEDTLS_GCM_DECRYPT, IV, sizeof(IV), NULL, 0);

        /*
         * Decrypt and write the plaintext.
         */
        for( offset = 0; offset < filesize; offset += 16 )
        {
            n = ( filesize - offset > 16 ) ? 16 : (int)
                ( filesize - offset );

            if( fread( buffer, 1, n, fin ) != n )
            {
                mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
                goto exit;
            }

            memcpy( tmp, buffer, n );

	    mbedtls_gcm_update( &gcm_ctx, n, tmp, buffer);

            if( fwrite( buffer, 1, n, fout ) != (size_t) n )
            {
                mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", n );
                goto exit;
            }
        }

        /*
         * Verify the message authentication code.
         */
	mbedtls_gcm_finish( &gcm_ctx, digest, sizeof(digest));

        if( fread( buffer, 1, 16, fin ) != 16 )
        {
            mbedtls_fprintf( stderr, "fread(%d bytes) failed\n", 16 );
            goto exit;
        }

        /* Use constant-time buffer comparison */
        diff = 0;
        for( i = 0; i < 16; i++ )
            diff |= digest[i] ^ buffer[i];

        if( diff != 0 )
        {
            mbedtls_fprintf( stderr, "HMAC check failed: wrong key, or file corrupted.\n" );
            goto exit;
        }
    }

    ret = 0;

exit:
    if( fin )
        fclose( fin );
    if( fout )
        fclose( fout );

    /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[4]. */
    for( i = 0; i < (unsigned int) argc; i++ )
        memset( argv[i], 0, strlen( argv[i] ) );

    memset( IV,     0, sizeof( IV ) );
    memset( key,    0, sizeof( key ) );
    memset( tmp,    0, sizeof( tmp ) );
    memset( buffer, 0, sizeof( buffer ) );
    memset( digest, 0, sizeof( digest ) );

    mbedtls_gcm_free( &gcm_ctx );
    mbedtls_entropy_free( &entropy_ctx );
    mbedtls_ctr_drbg_free( &ctr_drbg_ctx );

    return( ret );
}
#endif /* MBEDTLS_AES_C && MBEDTLS_SHA256_C && MBEDTLS_FS_IO */
