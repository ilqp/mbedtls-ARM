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
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"

#define PERSIST_AES_KEY_MATERIAL
#define USE_PERSISTED_AES_KEY_MATERIAL
typedef struct
{
	mbedtls_ecp_group grp;   /*!< The elliptic curve used. */
	mbedtls_mpi d;           /*!< The private key of agent. */
	mbedtls_ecp_point Q;     /*!< The public key of agent. */
	mbedtls_ecp_point Qp;    /*!< The public key of the server. */
	mbedtls_mpi z;           /*!< The shared secret. */
}
server_enc_context_t;

typedef struct {
	unsigned char *key;
	unsigned char *IV;
	size_t keylen_bits;
} aes_key_t;

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

static void print_buffer(char *title, unsigned char *ptr, size_t len) {
	printf("%s", title);
	for(size_t i = 0; i < len; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

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

int enc_to_server(unsigned char *in_aes_key, unsigned char *output_buff,
                  mbedtls_ctr_drbg_context *ctr_drbg_ctx) {

	((void) in_aes_key);
	((void) output_buff);

	server_enc_context_t enc_ctx;

	int curve = MBEDTLS_ECP_DP_SECP256R1;
	int ret = 1;

	/*
	 * Initialize required contexts.
	 */
	server_enc_context_init( &enc_ctx );

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
	ret = generate_client_keypair( &enc_ctx, ctr_drbg_ctx );
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
	ret = compute_shared_key( &enc_ctx, ctr_drbg_ctx );
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
	return ret;

}

#ifdef USE_PERSISTED_AES_KEY_MATERIAL
int read_aes_key_material( aes_key_t *aes_key ) {
	print_progress( (char *)"  . Read AES Key material from persistent storage..." );
	FILE *f_aes_key = NULL, *f_aes_iv = NULL;

	if( ( f_aes_key = fopen( "aes_key.bin", "rb" ) ) == NULL ) {
		printf( "  . fopen(aes_key.bin,rb) failed\n" );
		return -1;
	}

	if( ( f_aes_iv = fopen( "aes_iv.bin", "rb+" ) ) == NULL ) {
		printf( "  . fopen(aes_iv.bin,wb+) failed\n" );
		fclose( f_aes_key );
		return -1;
	}

	if(aes_key->IV)
		free( aes_key->IV );
	aes_key->IV = (unsigned char *) malloc(12);

	if( fread( aes_key->IV, 1, 12, f_aes_iv ) != 12 ) {
		printf("  . fread of AES IV failed\n");
		fclose( f_aes_key ), fclose( f_aes_iv );
		free( aes_key->IV );
		return -1;
	}
	fclose( f_aes_iv );

	if( aes_key->key )
		free( aes_key->key );

	int keylen = 0;
	aes_key->key = (unsigned char *) malloc( 32 );
	keylen = fread( aes_key->key, 1, 32, f_aes_key );

	if( keylen != 16 && keylen != 24 && keylen != 32 ) {
		printf("  . fread of AES Key failed\n");
		fclose(f_aes_key);
		free( aes_key->key ), free( aes_key->IV );
		return -1;
	}
	printf(" OK!\n");

	aes_key->keylen_bits = keylen * 8;

#ifndef DDEBUG
	print_buffer( (char *)"  . AES Key: ", aes_key->key, aes_key->keylen_bits/8 );
	print_buffer( (char *)"  . AES IV : ", aes_key->IV, 12 );
#endif
	return 0;
}
#endif // USE_PERSISTED_AES_KEY_MATERIAL

int aes_key_init(aes_key_t *aes_key, size_t keylen_bits, mbedtls_ctr_drbg_context *ctr_drbg_ctx,
                 mbedtls_md_context_t *sha_ctx) {
	size_t keylen;
	int ret = 1;

	/*
	 * Sanity check for Key lengths.
	 */
	if( keylen_bits != 128 || keylen_bits != 192 || keylen_bits != 256 )
		keylen = 32, keylen_bits = 256;
	else
		keylen = keylen_bits / 8;

	if(aes_key->key)
		free( aes_key->key );

	aes_key->key = (unsigned char *) malloc(keylen);
	aes_key->keylen_bits = keylen_bits;

	/*
	* Generate random data for AES Key and IV
	*/
	print_progress( (char *)"  . Generate random data for AES Key material... ");
	ret = mbedtls_ctr_drbg_random( ctr_drbg_ctx, aes_key->key, keylen );
	if( ret != 0 ) {
		printf("  . mbedtls_ctr_drbg_random() failed, ret = %d\n", ret), fflush(stdout);
		free(aes_key->key);
		return ret;
	}
	printf("  OK!\n");

	if(aes_key->IV)
		free( aes_key->IV );
	aes_key->IV = (unsigned char *) malloc(12);

	print_progress( (char *)"  . Generate random data for AES IV");
	ret = mbedtls_ctr_drbg_random( ctr_drbg_ctx, aes_key->IV, 12 );
	if( ret != 0 ) {
		printf("  . mbedtls_ctr_drbg_random() failed, ret = %d\n", ret), fflush(stdout);
		free(aes_key->key), free(aes_key->IV);
		return ret;
	}
	printf("  OK!\n");

#ifndef DDEBUG
	print_buffer( (char *)"  . AES Key before HKDF : ", aes_key->key, aes_key->keylen_bits/8 );
#endif
	/*
	 * Use HKDF to increase the entropy of random AES Key material.
	 */
	print_progress( (char *)"  . Use HKDF over random AES key to add more entropy...");
	ret = mbedtls_hkdf_extract(sha_ctx->md_info, NULL, 0, aes_key->key, aes_key->keylen_bits/8, aes_key->key);
	if( ret != 0 ) {
		printf("  . mbedtls_hkdf_extract() failed, ret = %d\n", ret ), fflush(stdout);
		free(aes_key->key), free(aes_key->IV);
		return ret;
	}
	printf("  OK!\n");

#ifndef DDEBUG
	print_buffer( (char *)"  . AES Key after HKDF :  ", aes_key->key, aes_key->keylen_bits/8 );
	print_buffer( (char *)"  . AES IV : ", aes_key->IV, 12 );
#endif

#ifdef PERSIST_AES_KEY_MATERIAL
	print_progress( (char *)"  . Write AES Key material to persistent storage..." );
	FILE *f_aes_key = NULL, *f_aes_iv = NULL;

	if( ( f_aes_key = fopen( "aes_key.bin", "wb" ) ) == NULL ) {
		printf("  . fopen(aes_key.bin,rb) failed\n");
		return -1;
	}

	if( ( f_aes_iv = fopen( "aes_iv.bin", "wb" ) ) == NULL ) {
		printf("  . fopen(aes_iv.bin,wb+) failed\n");
		fclose(f_aes_key);
		return -1;
	}

	if( fwrite( aes_key->IV, 1, 12, f_aes_iv ) != 12 ) {
		printf("  . fwrite of AES IV failed\n");
		fclose(f_aes_key), fclose(f_aes_iv);
		free(aes_key->IV);
		return -1;
	}
	fclose(f_aes_iv);

	if( fwrite( aes_key->key, 1, aes_key->keylen_bits / 8, f_aes_key ) != aes_key->keylen_bits / 8) {
		printf("  . fwrite of AES Key failed\n");
		fclose(f_aes_key);
		free( aes_key->key ), free( aes_key->IV );
		return -1;
	}
	printf(" OK!\n");

	aes_key->keylen_bits = keylen * 8;
#endif // PERSIST_AES_KEY_MATERIAL

	return ret;
}

void aes_free( aes_key_t *aes_key ) {
	if( aes_key->key ) free(aes_key->key);
	if( aes_key->IV ) free(aes_key->IV);
}

int main() {
	int ret = 1;

	aes_key_t aes_key;
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_context ctr_drbg_ctx;
	mbedtls_md_context_t sha_ctx;

	mbedtls_entropy_init( &entropy_ctx );
	mbedtls_ctr_drbg_init( &ctr_drbg_ctx );
	mbedtls_md_init( &sha_ctx );

	/*
	 * Seed the random number generator.
	 */
	print_progress( (char *)"  . Seeding the random number generator..." );
	ret = mbedtls_ctr_drbg_seed( &ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
	                             // (const unsigned char *) "RANDOM_GEN", 10 );
	if( ret != 0 ) {
		printf( "  . failed!\n\n\t . mbedtls_ctr_drbg_seed() returned %d", ret), fflush(stdout);
		goto exit;
	}

	mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg_ctx, MBEDTLS_CTR_DRBG_PR_OFF );
	print_progress(  (char *)"  . OK!\n");

	/*
	 * Setup SHA-256 as MD for HKDF.
	 */
	print_progress( (char *)"  . Setup SHA-256 MD for HKDF...");
	ret = mbedtls_md_setup( &sha_ctx, mbedtls_md_info_from_type( MBEDTLS_MD_SHA256 ), 1 );
	if( ret != 0 ) {
		printf( "  ! mbedtls_md_setup() returned -0x%04x\n", -ret );
		return ret;
	}
	printf("  OK!\n");

	/*
	 * Initialize the AES Key and IV.
	 */
#ifdef USE_PERSISTED_AES_KEY_MATERIAL
	print_progress( (char *)"  . Read previously persisted ephemeral AES Key and IV... STARTED!\n" );
	ret = read_aes_key_material( &aes_key );
	if( ret != 0 ) {
		goto exit;
	}
	print_progress( (char *)"  . Read previously persisted ephemeral AES Key and IV... OK!\n" );
#else // USE_PERSISTED_AES_KEY_MATERIAL
	print_progress( (char *)"  . Generate ephemeral AES Key and IV... STARTED!\n" );
	ret = aes_key_init( &aes_key, 256, &ctr_drbg_ctx, &sha_ctx );
	if( ret != 0 ) {
		goto exit;
	}
	print_progress( (char *)"  . Generate ephemeral AES Key and IV... OK!\n" );
#endif // USE_PERSISTED_AES_KEY_MATERIAL

	exit(0);

	unsigned char *output_buff = NULL;

	print_progress( (char *)"  . Start Encryption to Server... STARTED!\n");
	ret = enc_to_server(aes_key.key, output_buff, &ctr_drbg_ctx);
	if( ret != 0 ) {
		printf("  . Start Encryption to Server... Failed\n  . enc_to_server() return %d", ret );
	}
exit:

	mbedtls_ctr_drbg_free( &ctr_drbg_ctx );
	mbedtls_entropy_free( &entropy_ctx);
	aes_free( &aes_key );
	return ret;
}
