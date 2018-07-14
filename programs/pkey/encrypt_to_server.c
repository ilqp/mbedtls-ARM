/*
 *  Example ECDHE with secp256r1 program
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
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_ECDH_C) || \
    !defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or "
                    "MBEDTLS_ECP_DP_SECP256R1_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

static void print_ecp_group_id_name(mbedtls_ecp_group_id id) {
    switch(id) {
    case MBEDTLS_ECP_DP_NONE:        printf("\t Curve : MBEDTLS_ECP_DP_NONE\n"); break;
    case MBEDTLS_ECP_DP_SECP192R1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP192R1\n"); break;
    case MBEDTLS_ECP_DP_SECP224R1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP224R1\n"); break;
    case MBEDTLS_ECP_DP_SECP256R1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP256R1\n"); break;
    case MBEDTLS_ECP_DP_SECP384R1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP384R1\n"); break;
    case MBEDTLS_ECP_DP_SECP521R1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP521R1\n"); break;
    case MBEDTLS_ECP_DP_BP256R1:     printf("\t Curve : MBEDTLS_ECP_DP_BP256R1\n"); break;
    case MBEDTLS_ECP_DP_BP384R1:     printf("\t Curve : MBEDTLS_ECP_DP_BP384R1\n"); break;
    case MBEDTLS_ECP_DP_BP512R1:     printf("\t Curve : MBEDTLS_ECP_DP_BP512R1\n"); break;
    case MBEDTLS_ECP_DP_CURVE25519:  printf("\t Curve : MBEDTLS_ECP_DP_CURVE25519\n"); break;
    case MBEDTLS_ECP_DP_SECP192K1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP192K1\n"); break;
    case MBEDTLS_ECP_DP_SECP224K1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP224K1\n"); break;
    case MBEDTLS_ECP_DP_SECP256K1:   printf("\t Curve : MBEDTLS_ECP_DP_SECP256K1\n"); break;
    case MBEDTLS_ECP_DP_CURVE448:    printf("\t Curve : MBEDTLS_ECP_DP_CURVE448\n"); break;
    }
}

static void print_ecp_point(mbedtls_ecp_point pt) {
    mbedtls_mpi_write_file("\tX: ", &pt.X, 16, NULL);
    mbedtls_mpi_write_file("\tY: ", &pt.Y, 16, NULL);
    mbedtls_mpi_write_file("\tZ: ", &pt.Z, 16, NULL);
}
static void print_ecp_group(mbedtls_ecp_group grp) {
    mbedtls_printf("Information about group:\n");
    print_ecp_group_id_name(grp.id);
    mbedtls_mpi_write_file("grp.P: ", &grp.P, 16, NULL);
    mbedtls_mpi_write_file("grp.A: ", &grp.A, 16, NULL);
    mbedtls_mpi_write_file("grp.B: ", &grp.B, 16, NULL);
    mbedtls_mpi_write_file("grp.N: ", &grp.N, 16, NULL);
    mbedtls_printf("grp.G\n");
    print_ecp_point(grp.G);
    mbedtls_printf("grp.pbits: %zu\n", grp.pbits);
    mbedtls_printf("grp.nbits: %zu\n", grp.nbits);
    mbedtls_printf("grp.h: %d\n", grp.h);
}

static void print_buffer(char *title, unsigned char *ptr, size_t len) {
	printf("%s", title);
	for(size_t i = 0; i < len; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}
int main( int argc, char *argv[] )
{
    int ret;
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srvx[32], srv_to_clix[32];
    unsigned char cli_to_srvy[32], srv_to_cliy[32];
    const char pers[] = "ecdh";
    ((void) argc);
    ((void) argv);

    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    int curve = MBEDTLS_ECP_DP_SECP256R1;

    /*
     * Initialize random number generation
     */
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    /*
     * Client: inialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up client context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_cli.grp, curve );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_printf("\n=======================================================================\n");
    print_ecp_group(ctx_cli.grp);
    mbedtls_printf("=======================================================================\n");

    ret = mbedtls_ecdh_gen_public( &ctx_cli.grp, &ctx_cli.d, &ctx_cli.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.X, cli_to_srvx, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.Y, cli_to_srvy, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_mpi_write_file("ctx_cli.d: ", &ctx_cli.d, 16, NULL);
    mbedtls_printf("ctx_cli.Q\n");
    print_ecp_point(ctx_cli.Q);
    print_buffer((char *)"cli_to_srvx: ", &cli_to_srvx[0], 32);
    print_buffer((char *)"cli_to_srvy: ", &cli_to_srvy[0], 32);
    mbedtls_printf("=======================================================================\n");

    mbedtls_printf( " ok\n" );

    /*
     * Server: initialize context and generate keypair
     */
    mbedtls_printf( "  . Setting up server context..." );
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_srv.grp, curve );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_printf("\n=======================================================================\n");
    print_ecp_group(ctx_srv.grp);
    mbedtls_printf("=======================================================================\n");

    FILE *f_srv_d, *f_srv_QX, *f_srv_QY;
#ifdef GENERATE_SERVER_KEY
    ret = mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q,
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    if( ( f_srv_d = fopen( "srv_d.bin", "wb" ) ) != NULL )
    {
    	mbedtls_printf("  . Write server private key to srv_d.bin ");
    	ret = mbedtls_mpi_write_file(NULL, &ctx_srv.d, 16, f_srv_d);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_d );
        mbedtls_printf( " ok\n" );
    }

    if( ( f_srv_QX = fopen( "srv_QX.bin", "wb" ) ) != NULL )
    {
    	mbedtls_printf("  . Write server Q.X to srv_QX.bin ");
    	ret = mbedtls_mpi_write_file(NULL, &ctx_srv.Q.X, 16, f_srv_QX);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_QX );
        mbedtls_printf( " ok\n" );
    }

    if( ( f_srv_QY = fopen( "srv_QY.bin", "wb" ) ) != NULL )
    {
    	mbedtls_printf("  . Write server Q.Y to srv_QY.bin ");
    	ret = mbedtls_mpi_write_file(NULL, &ctx_srv.Q.Y, 16, f_srv_QY);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_QY );
        mbedtls_printf( " ok\n" );
    }
#else
    if( ( f_srv_d = fopen( "srv_d.bin", "rb" ) ) != NULL )
    {
    	mbedtls_printf("  . Read server private key from srv_d.bin ");
    	ret = mbedtls_mpi_read_file(&ctx_srv.d, 16, f_srv_d);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_write_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_d );
        mbedtls_printf( " ok\n" );
    }

    if( ( f_srv_QX = fopen( "srv_QX.bin", "rb" ) ) != NULL )
    {
    	mbedtls_printf("  . Read server Q.X from srv_QX.bin ");
    	ret = mbedtls_mpi_read_file(&ctx_srv.Q.X, 16, f_srv_QX);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_QX );
        mbedtls_printf( " ok\n" );
    }

    if( ( f_srv_QY = fopen( "srv_QY.bin", "rb" ) ) != NULL )
    {
    	mbedtls_printf("  . Read server Q.Y from srv_QY.bin ");
    	ret = mbedtls_mpi_read_file(&ctx_srv.Q.Y, 16, f_srv_QY);
        if( ret != 0 )
        {
            mbedtls_printf( " failed\n  ! mbedtls_mpi_read_file returned %d\n", ret );
            goto exit;
        }
        fclose( f_srv_QY );
        mbedtls_printf( " ok\n" );
    }
#endif

    ret = mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_clix, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_srv.Q.Y, srv_to_cliy, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_mpi_write_file("ctx_srv.d: ", &ctx_srv.d, 16, NULL);
    mbedtls_printf("ctx_srv.Q\n");
    print_ecp_point(ctx_srv.Q);
    print_buffer((char *)"srv_to_clix: ", &srv_to_clix[0], 32);
    print_buffer((char *)"srv_to_cliy: ", &srv_to_cliy[0], 32);
    mbedtls_printf("=======================================================================\n");
    mbedtls_printf( " ok\n" );

    /*
     * Server: read peer's key and generate shared secret
     */
    mbedtls_printf( "  . Server reading client key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.X, cli_to_srvx, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.Y, cli_to_srvy, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_printf("\n");
    mbedtls_printf("ctx_srv.Qp\n");
    print_ecp_point(ctx_srv.Qp);
    ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp, &ctx_srv.z,
                                       &ctx_srv.Qp, &ctx_srv.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_mpi_write_file("ctx_srv.z: ", &ctx_srv.z, 16, NULL);
    mbedtls_printf("=======================================================================\n");
    mbedtls_printf( " ok\n" );

    /*
     * Client: read peer's key and generate shared secret
     */
    mbedtls_printf( "  . Client reading server key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_clix, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.Y, srv_to_cliy, 32 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z,
                                       &ctx_cli.Qp, &ctx_cli.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    // SHINGU
    mbedtls_printf("\n");
    mbedtls_printf("ctx_cli.Qp\n");
    print_ecp_point(ctx_cli.Qp);
    mbedtls_mpi_write_file("ctx_cli.z: ", &ctx_cli.z, 16, NULL);
    mbedtls_printf("Length of ctx_cli.z in bits: %zu\n", mbedtls_mpi_bitlen(&ctx_cli.z));
    mbedtls_printf("=======================================================================\n");
    mbedtls_printf( " ok\n" );

    /*
     * Verification: are the computed secrets equal?
     */
    mbedtls_printf( "  . Checking if both computed secrets are equal..." );
    fflush( stdout );

    ret = mbedtls_mpi_cmp_mpi( &ctx_cli.z, &ctx_srv.z );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


exit:

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ecdh_free( &ctx_srv );
    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret != 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_SECP256R1_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
