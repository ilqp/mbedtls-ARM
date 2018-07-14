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

#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

typedef struct
{
	mbedtls_ecp_group grp;   /*!< The elliptic curve used. */
	mbedtls_mpi d;           /*!< The private key of agent. */
	mbedtls_ecp_point Q;     /*!< The public key of agent. */
	mbedtls_ecp_point Qp;    /*!< The public key of the server. */
	mbedtls_mpi z;           /*!< The shared secret. */
}
server_enc_context_t;

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
	mbedtls_mpi_write_file("    X: ", &pt.X, 16, NULL);
	mbedtls_mpi_write_file("    Y: ", &pt.Y, 16, NULL);
	mbedtls_mpi_write_file("    Z: ", &pt.Z, 16, NULL);
}

static void print_ecp_group(mbedtls_ecp_group grp) {
	printf("Information about group:\n");
    	print_ecp_group_id_name(grp.id);
	mbedtls_mpi_write_file("grp.P: ", &grp.P, 16, NULL);
	mbedtls_mpi_write_file("grp.A: ", &grp.A, 16, NULL);
	mbedtls_mpi_write_file("grp.B: ", &grp.B, 16, NULL);
	printf("grp.G:\n");
	print_ecp_point(grp.G);
	mbedtls_mpi_write_file("grp.N: ", &grp.N, 16, NULL);
	printf("grp.pbits: %zu\n", grp.pbits);
	printf("grp.nbits: %zu\n", grp.nbits);
	printf("grp.h: %d\n", grp.h);
}

#if 0
static void print_buffer(char *title, unsigned char *ptr, size_t len) {
	printf("%s", title);
	for(size_t i = 0; i < len; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}
#endif

void print_progress(char *msg) {
	printf("%s", msg), fflush( stdout );
}

int generate_client_keypair( server_enc_context_t *enc_ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx) {
	int ret = 1;
	ret = mbedtls_ecdh_gen_public( &enc_ctx->grp, &enc_ctx->d, &enc_ctx->Q,
				       mbedtls_ctr_drbg_random, ctr_drbg_ctx );
	if( ret != 0 ) {
		printf( " failed!\n\n\t . mbedtls_ecdh_gen_public() returned %d\n", ret ), fflush(stdout);
		return ret;
	}
	/*
	 * SECP256R1 curves Z coordinates are set to 1.
	 */
	ret = mbedtls_mpi_lset( &enc_ctx->Q.Z, 1 );
	if( ret != 0 ) {
		printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret ), fflush(stdout);
	}

	return ret;
}

int read_server_pkey( mbedtls_ecp_point *Qp) {

	FILE *f_srv_QX = NULL;
	FILE *f_srv_QY = NULL;

	int ret = 1;
	/*
	 * Open the files containing servers public key
	 */
	if( ( f_srv_QX = fopen( "srv_QX.bin", "rb" ) ) == NULL ) {
		printf( " failed\n\n\t ! Unable to open srv_QX.bin\n");
		return -1;
	}

	if( ( f_srv_QY = fopen( "srv_QY.bin", "rb" ) ) == NULL ) {
		printf( " failed\n\n\t ! Unable to open srv_QY.bin\n");
		fclose( f_srv_QX );
		return -1;
	}

	/*
	 * Read X and Y coordinates of server public key.
	 */
	ret = mbedtls_mpi_read_file( &Qp->X, 16, f_srv_QX );
	fclose( f_srv_QX );

	if( ret != 0 ) {
		printf( " failed\n\n\t ! mbedtls_mpi_read_file() returned %d\n", ret ), fflush(stdout);
		return ret;
	}

	ret = mbedtls_mpi_read_file(&Qp->Y, 16, f_srv_QY);
	fclose( f_srv_QY );

	if( ret != 0 ) {
		printf( " failed\n\n\t ! mbedtls_mpi_read_file() returned %d\n", ret ), fflush(stdout);
		return ret;
	}

	/*
	 * SECP256R1 curves Z coordinates are set to 1.
	 */
	ret = mbedtls_mpi_lset( &Qp->Z, 1 );
	if( ret != 0 ) {
		printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret ), fflush(stdout);
	}

	return ret;
}

int compute_shared_key( server_enc_context_t *enc_ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx) {
	return mbedtls_ecdh_compute_shared( &enc_ctx->grp, &enc_ctx->z, &enc_ctx->Qp, &enc_ctx->d,
					   mbedtls_ctr_drbg_random, ctr_drbg_ctx );
}

void server_enc_context_init(server_enc_context_t *enc_ctx) {
	memset( enc_ctx, 0, sizeof( server_enc_context_t ) );
}

void server_enc_context_free(server_enc_context_t *enc_ctx) {
	if( enc_ctx == NULL) return;

	mbedtls_ecp_group_free( &enc_ctx->grp );
	mbedtls_ecp_point_free( &enc_ctx->Q   );
	mbedtls_ecp_point_free( &enc_ctx->Qp  );
	mbedtls_mpi_free( &enc_ctx->d  );
	mbedtls_mpi_free( &enc_ctx->z  );
}
int enc_to_server(unsigned char *in_aes_key, unsigned char *output_buff) {

	((void) in_aes_key);
	((void) output_buff);

	server_enc_context_t enc_ctx;
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_context ctr_drbg_ctx;

	int curve = MBEDTLS_ECP_DP_SECP256R1;
	int ret = 1;

	/*
	 * Initialize required contexts.
	 */
	server_enc_context_init( &enc_ctx );
	mbedtls_entropy_init( &entropy_ctx );
	mbedtls_ctr_drbg_init( &ctr_drbg_ctx );

	/*
	 * Seed the random number generator.
	 */
	print_progress( (char *)"  . Seeding the random number generator..." );
	ret = mbedtls_ctr_drbg_seed( &ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
	                             // (const unsigned char *) "RANDOM_GEN", 10 );
	if( ret != 0 ) {
		printf( "  . failed!\n\n\t . mbedtls_ctr_drbg_seed() returned %d", ret), fflush(stdout);
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

	/*
	 * Load the group information.
	 */
	print_progress(  (char *)"  . Load the group information for the ECC..." );
	ret = mbedtls_ecp_group_load( &enc_ctx.grp, curve );
	if( ret != 0 ) {
		printf( " failed!\n\n\t . mbedtls_ecp_group_load() returned %d\n", ret ), fflush(stdout);
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	print_ecp_group(enc_ctx.grp);
#endif

	/*
	 * Generate client's public key pair;
	 */
	print_progress(  (char *)"  . Generating public key pair for client..." );
	ret = generate_client_keypair( &enc_ctx, &ctr_drbg_ctx );
	if( ret != 0 ) {
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	mbedtls_mpi_write_file("enc_ctx.d: ", &enc_ctx.d, 16, NULL);
	mbedtls_printf("enc_ctx.Q:\n");
	print_ecp_point(enc_ctx.Q);
#endif

	// ret = read_client_keypair(&enc_ctx.d, &enc_ctx.Q);

	/*
	 * Load the servers public key
	 */
	print_progress(  (char *)"  . Load the servers public key into context..." );
	ret = read_server_pkey( &enc_ctx.Qp);
	if( ret != 0 ) {
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	printf("enc_ctx.Qp:\n");
	print_ecp_point(enc_ctx.Qp);
#endif

	print_progress(  (char *)"  . Compute the shared secret..." );
	ret = compute_shared_key( &enc_ctx, &ctr_drbg_ctx );
	if( ret != 0 ) {
		printf( " failed\n  ! compute_shared_key() returned %d\n", ret ), fflush(stdout);
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	mbedtls_mpi_write_file("enc_ctx.z: ", &enc_ctx.z, 16, NULL);
	printf("Length of enc_ctx.z in bits: %zu\n", mbedtls_mpi_bitlen(&enc_ctx.z));
#endif
	// ret = compute_shared_aes_key( &enc_ctx.z, shared_aes_key );

	// ret = _enc_to_server( &enc_ctx, &in_aes_key, &output_buff );

cleanup:
	server_enc_context_free( &enc_ctx );
	mbedtls_ctr_drbg_free( &ctr_drbg_ctx );
	mbedtls_entropy_free( &entropy_ctx );
	return ret;

}

int main() {
	unsigned char *in_aes_key = NULL;
	unsigned char *output_buff = NULL;
	enc_to_server(in_aes_key, output_buff);
}
