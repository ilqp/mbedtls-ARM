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

#include <unistd.h>
#include <string.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/md.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/gcm.h"

/*
 * Macros to control the operation
 */

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  %s <mode> <input filename> <output filename>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n"

#define PERSIST_AES_KEY_MATERIAL
#define USE_PERSISTED_AES_KEY_MATERIAL

#define PERSIST_CLIENT_KEY_MATERIAL
#define USE_PERSISTED_CLIENT_KEY_MATERIAL

#define PERSIST_SERVER_KEY_MATERIAL
#define USE_PERSISTED_SERVER_KEY_MATERIAL

#define DEBUG
#define TRACK_PROGRESS

#define CHECK_AND_RET( x ) { if ( (ret = x) != 0) return ret; }
/*
 *  The minimal ECDH context structure.
 */
typedef struct
{
    mbedtls_ecp_group grp;   /*!< The elliptic curve used. */
    mbedtls_mpi d;           /*!< The private key. */
    mbedtls_ecp_point Q;     /*!< The public key. */
    mbedtls_ecp_point Qp;    /*!< The value of the public key of the peer. */
    mbedtls_mpi z;           /*!< The shared secret. */
}
_mbedtls_ecdh_context;

typedef struct {
	unsigned char *key;
	unsigned char *IV;
	size_t keylen_bits;
} aes_key_t;

/*
 * Context init and free
 */

void _mbedtls_ecdh_context_init(_mbedtls_ecdh_context *enc_ctx) {
	memset( enc_ctx, 0, sizeof( _mbedtls_ecdh_context ) );
}

void _mbedtls_ecdh_context_free(_mbedtls_ecdh_context *enc_ctx) {
	if( enc_ctx == NULL) return;

	mbedtls_ecp_group_free( &enc_ctx->grp );
	mbedtls_ecp_point_free( &enc_ctx->Q   );
	mbedtls_ecp_point_free( &enc_ctx->Qp  );
	mbedtls_mpi_free( &enc_ctx->d  );
	mbedtls_mpi_free( &enc_ctx->z  );
}

void aes_key_init( aes_key_t *aes_key, size_t key_len, size_t iv_len) {
	if(aes_key->key) free( aes_key->key );
	if(aes_key->IV) free( aes_key->IV );

	aes_key->key = (unsigned char *) malloc(key_len);
	aes_key->IV = (unsigned char *) malloc(iv_len);
}

void aes_free( aes_key_t *aes_key ) {
	if( aes_key->key ) free(aes_key->key);
	if( aes_key->IV ) free(aes_key->IV);
}

/*
 * Utility functions
 */

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

int persist_aes_key_material(aes_key_t *aes_key, char *key_fname, char *iv_fname) {
	FILE *f = NULL;

	if( ( f = fopen( key_fname, "wb" ) ) == NULL ) {
		printf("  . fopen(%s,rb) failed\n", key_fname);
		return -1;
	}
	if( fwrite( aes_key->key, 1, aes_key->keylen_bits / 8, f ) != aes_key->keylen_bits / 8) {
		printf("  . fwrite of AES Key failed\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	if( ( f = fopen( iv_fname, "wb" ) ) == NULL ) {
		printf("  . fopen(%s,wb+) failed\n", iv_fname);
		return -1;
	}

	if( fwrite( aes_key->IV, 1, 12, f ) != 12 ) {
		printf("  . fwrite of AES IV failed\n");
		fclose(f);
		return -1;
	}
	fclose(f);

	return 0;
}

int generate_ec_keypair( _mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx) {
	int ret = 1;
	ret = mbedtls_ecdh_gen_public( &ctx->grp, &ctx->d, &ctx->Q,
				       mbedtls_ctr_drbg_random, ctr_drbg_ctx );
	if( ret != 0 ) {
		printf( " failed!\n\n\t . mbedtls_ecdh_gen_public() returned %d\n", ret ), fflush(stdout);
		return ret;
	}
	/*
	 * SECP256R1 curves Z coordinates are set to 1.
	 */
	ret = mbedtls_mpi_lset( &ctx->Q.Z, 1 );
	if( ret != 0 ) {
		printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret ), fflush(stdout);
	}

	return ret;
}

int read_hexmpi_from_file( mbedtls_mpi *mp, char *fname) {
	FILE *f = NULL;

	if( ( f = fopen( fname, "rb" ) ) == NULL ) {
		printf(" failed\n\n\t ! fopen(%s,rb) failed\n", fname);
		return -1;
	}

	int ret = mbedtls_mpi_read_file( mp, 16, f );
	fclose( f );

	if( ret != 0 ) {
		printf( " failed\n\n\t ! mbedtls_mpi_read_file( %s ) returned %d\n",fname, ret );
		fflush(stdout);
		return ret;
	}

	return 0;
}

int write_hexmpi_from_file( mbedtls_mpi *mp, char *fname) {
	FILE *f = NULL;

	if( ( f = fopen( fname, "wb" ) ) == NULL ) {
		printf(" failed\n\n\t ! fopen(%s,wb) failed\n", fname);
		return -1;
	}

	int ret = mbedtls_mpi_write_file( NULL, mp, 16, f );
	fclose( f );

	if( ret != 0 ) {
		printf( " failed\n\n\t ! mbedtls_mpi_write_file( %s ) returned %d\n",fname, ret );
		fflush(stdout);
		return ret;
	}

	return 0;
}

int read_ec_keypair( mbedtls_mpi *d, mbedtls_ecp_point *Q, char *d_fname, char *QX_fname, char *QY_fname, char *QZ_fname ) {
	int ret = 1;

	if( d_fname )
		CHECK_AND_RET( read_hexmpi_from_file( d, d_fname) );

	if( QX_fname )
		CHECK_AND_RET( read_hexmpi_from_file( &Q->X, QX_fname) );

	if( QY_fname )
		CHECK_AND_RET( read_hexmpi_from_file( &Q->Y, QY_fname) );

	if( QZ_fname )
		CHECK_AND_RET( read_hexmpi_from_file( &Q->Z, QZ_fname) );

	return ret;
}

int write_ec_keypair( mbedtls_mpi *d, mbedtls_ecp_point *Q, char *d_fname, char *QX_fname, char *QY_fname, char *QZ_fname ) {
	int ret = 1;

	if( d_fname )
		CHECK_AND_RET( write_hexmpi_from_file( d, d_fname) );

	if( QX_fname )
		CHECK_AND_RET( write_hexmpi_from_file( &Q->X, QX_fname) );

	if( QY_fname )
		CHECK_AND_RET( write_hexmpi_from_file( &Q->Y, QY_fname) );

	if( QZ_fname )
		CHECK_AND_RET( write_hexmpi_from_file( &Q->Z, QZ_fname) );

	return 0;
}

int read_fbuffer( char *fname, FILE *fp, unsigned char *ptr, size_t len) {
	FILE *f = fp;

	int close_file = 1;
	if ( f )
		close_file = 0;

	if( !f && (f = fopen(fname, "rb")) == NULL ){
		printf(" . fopen(%s, rb) failed\n", fname);
		return -1;
	}

	size_t ret = fread( ptr, 1, len, f );
	if( close_file )
		fclose( f );

	if( ret != len ) {
		printf("  . fread(%s) read %zd instead of %zd from failed\n", fname, ret, len);
		return ret;
	}

	return 0;
}

int compute_shared_key( _mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx) {
	return mbedtls_ecdh_compute_shared( &ctx->grp, &ctx->z, &ctx->Qp, &ctx->d,
					   mbedtls_ctr_drbg_random, ctr_drbg_ctx );
}

int ecdh_init(_mbedtls_ecdh_context *ctx) {

	int curve = MBEDTLS_ECP_DP_SECP256R1;
	int ret = 1;

	/*
	 * Initialize required contexts.
	 */
	_mbedtls_ecdh_context_init( ctx );

	/*
	 * Load the group information.
	 */
	print_progress(  (char *)"  . Load the group information for the ECC..." );
	ret = mbedtls_ecp_group_load( &ctx->grp, curve );
	if( ret != 0 ) {
		printf( " failed!\n\n\t . mbedtls_ecp_group_load() returned %d\n", ret ), fflush(stdout);
		return ret;
	}
	print_progress(  (char *)"  . OK!\n");

#ifdef DDEBUG
	printf("===========================================================================\n");
	print_ecp_group(ctx->grp);
#endif
	return 0;
}

int ecdh_init_Q( _mbedtls_ecdh_context *ctx, mbedtls_ctr_drbg_context *ctr_drbg_ctx,
                 char *d_fname, char *QX_fname, char *QY_fname, char *QZ_fname) {
	int ret;
	/*
	 * Read client's key material from persisted file;
	 */
	print_progress(  (char *)"  . Try to read (d, Q) from persisted file..." );
	ret = read_ec_keypair( &ctx->d, &ctx->Q, d_fname, QX_fname, QY_fname, QZ_fname);
	if( ret != 0 ) {
			/*
			 * Generate client's public key pair;
			 */
			print_progress(  (char *)"  . Try to read (d, Q) from persisted file..." );
			print_progress(  (char *)"  . Generating (d,Q)..." );
			ret = generate_ec_keypair( ctx, ctr_drbg_ctx );
			if( ret != 0 ) {
				return ret;
			}
			print_progress(  (char *)"  . OK!\n");

		#ifdef PERSIST_CLIENT_KEY_MATERIAL
			printf("Persist client key...\n");
			write_ec_keypair(&ctx->d, &ctx->Q, d_fname, QX_fname, QY_fname, QZ_fname);
		#endif // PERSIST_CLIENT_KEY_MATERIAL

	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	mbedtls_mpi_write_file("ctx->d: ", &ctx->d, 16, NULL);
	mbedtls_printf("ctx->Q:\n");
	print_ecp_point(ctx->Q);
#endif
	return 0;
}

int ecdh_init_Qp( _mbedtls_ecdh_context *ctx, char *QX_fname, char *QY_fname, char *QZ_fname) {
	/*
	 * Load the servers public key
	 */
	int ret = 1;
	print_progress(  (char *)"  . Load the servers public key into context..." );
	ret = read_ec_keypair( NULL, &ctx->Qp, NULL, QX_fname, QY_fname, QZ_fname );
	if( ret != 0 ) {
		return ret;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	printf("ctx->Qp:\n");
	print_ecp_point(ctx->Qp);
#endif
	return ret;
}

int ec_operation ( unsigned char *in_aes_key, unsigned char *out_aes_key, int mode,
                   mbedtls_ctr_drbg_context *ctr_drbg_ctx, mbedtls_md_context_t *sha_ctx) {

	_mbedtls_ecdh_context ctx;
	int ret = 1;

	print_progress(  (char *)"  . ECDH Init... STARTED!\n" );
	ret = ecdh_init(&ctx);
	if( ret != 0 ) {
		printf( " failed!\n\n\t . ecdh_init() returned %d\n", ret ), fflush(stdout);
		goto cleanup;
	}
	print_progress(  (char *)"  . ECDH Init... OK!\n" );

	if(mode == MODE_ENCRYPT) {
		print_progress(  (char *)"  . ECDH Load Q... STARTED!\n" );
#ifdef USE_PERSISTED_CLIENT_KEY_MATERIAL
		ret = ecdh_init_Q( &ctx, ctr_drbg_ctx,
		             (char *)"cli_d.bin", (char *)"cli_QX.bin",
		             (char *)"cli_QY.bin", (char *)"cli_QZ.bin" );
#else
		ret = ecdh_init_Q( &ctx, ctr_drbg_ctx,
		                  (char *)"cli_d.bin", (char *)"cli_QX.bin",
		                  (char *)"cli_QY.bin", (char *)"cli_QZ.bin" );
#endif
		if( ret != 0 ) {
			printf( " failed!\n\n\t . ecdh_init_Q() returned %d\n", ret ), fflush(stdout);
			goto cleanup;
		}
		print_progress(  (char *)"  . ECDH Load Q... OK!\n" );

		/*
		 * Load the servers public key
		 */
		print_progress(  (char *)"  . Load the servers public key into context..." );
		ret = read_ec_keypair( NULL, &ctx.Qp, NULL, (char *)"srv_QX.bin", (char *)"srv_QY.bin", (char *)"srv_QZ.bin" );
		if( ret != 0 ) {
			goto cleanup;
		}
		print_progress(  (char *)"  . OK!\n");
	}
	else {
#ifdef USE_PERSISTED_SERVER_KEY_MATERIAL
		print_progress(  (char *)"  . ECDH Load Q... STARTED!\n" );
		ret = ecdh_init_Q( &ctx, ctr_drbg_ctx,
		                   (char *)"srv_d.bin", (char *)"srv_QX.bin",
		                   (char *)"srv_QY.bin", (char *)"srv_QZ.bin" );
#else
		ret = ecdh_init_Q( &ctx, ctr_drbg_ctx,
		                   (char *)"srv_d.bin", (char *)"srv_QX.bin",
		                   (char *)"srv_QY.bin", (char *)"srv_QZ.bin" );
#endif
		if( ret != 0 ) {
			printf( " failed!\n\n\t . ecdh_init_Q() returned %d\n", ret ), fflush(stdout);
			goto cleanup;
		}
		print_progress(  (char *)"  . ECDH Load Q... OK!\n" );
		/*
		 * Load the Client's public key
		 */
		print_progress(  (char *)"  . Load the Client's public key into context..." );
		ret = read_ec_keypair( NULL, &ctx.Qp, NULL, (char *)"cli_QX.bin", (char *)"cli_QY.bin", (char *)"cli_QZ.bin" );
		if( ret != 0 ) {
			goto cleanup;
		}
		print_progress(  (char *)"  . OK!\n");

	}
	print_progress(  (char *)"  . ECDH Load Q... OK!\n" );

#ifndef DDEBUG
	printf("===========================================================================\n");
	printf("ctx.Qp:\n");
	print_ecp_point(ctx.Qp);
#endif

	print_progress(  (char *)"  . Compute the shared secret..." );
	ret = compute_shared_key( &ctx, ctr_drbg_ctx );
	if( ret != 0 ) {
		printf( " failed\n  ! compute_shared_key() returned %d\n", ret ), fflush(stdout);
		goto cleanup;
	}
	print_progress(  (char *)"  . OK!\n");

#ifndef DDEBUG
	printf("===========================================================================\n");
	mbedtls_mpi_write_file("ctx.z: ", &ctx.z, 16, NULL);
	printf("Length of ctx.z in bits: %zu\n", mbedtls_mpi_bitlen(&ctx.z));
#endif

	unsigned char *shared_aes_key = (unsigned char*) calloc(32,1);

	ret = mbedtls_mpi_write_binary( &ctx.z, shared_aes_key, 32 );
	if( ret != 0 ) {
		printf( " Failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
		goto cleanup;
	}
	print_buffer( (char*)"Shared AES Key in buffer: ", shared_aes_key, 32);

#ifndef DDEBUG
	print_buffer( (char *)"  . Shared AES Key before HKDF : ", shared_aes_key, 32 );
#endif
	/*
	 * Use HKDF to increase the entropy of random AES Key material.
	 */
	print_progress( (char *)"  . Use HKDF over shared AES key to add more entropy..." );
	ret = mbedtls_hkdf_extract(sha_ctx->md_info, NULL, 0, shared_aes_key, 32, shared_aes_key );
	if( ret != 0 ) {
		printf("  . mbedtls_hkdf_extract() failed, ret = %d\n", ret ), fflush(stdout);
		free( shared_aes_key );
		goto cleanup;
	}
	printf("  OK!\n");

#ifndef DDEBUG
	print_buffer( (char *)"  . Shared AES Key after HKDF :  ", shared_aes_key, 32 );
#endif

#ifndef DISABLE_VERIFICATION
	print_progress( (char *)"  . Print the length of final shared AES Key.\n");
	ret = mbedtls_mpi_read_binary( &ctx.z, shared_aes_key, 32 );
	if( ret != 0 ) {
		printf( " Failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
		goto cleanup;
	}

	mbedtls_mpi_write_file("shared_aes_key: ", &ctx.z, 16, NULL);
	printf("Length of shared_aes_key in bits: %zu\n", mbedtls_mpi_bitlen(&ctx.z));
	printf("===========================================================================\n");
#endif

	print_progress( (char *)"  . Encrypt the Ephemeral AES key with shared AES Key.  OK!\n");
	for( int i = 0; i < 32; i++ )
		out_aes_key[i] = (unsigned char)( in_aes_key[i] ^ shared_aes_key[i] );

	print_buffer( (char *)"Encrypted AES Key: ", out_aes_key, 32);

cleanup:
	_mbedtls_ecdh_context_free( &ctx );
	return ret;
}

#ifdef USE_PERSISTED_AES_KEY_MATERIAL
int read_aes_key_material( aes_key_t *aes_key ) {

	int ret = 1;

	CHECK_AND_RET( read_fbuffer( (char *)"aes_iv.bin", NULL, aes_key->IV, 12));

	int keylen = read_fbuffer( (char *)"aes_key.bin", NULL, aes_key->key, 32);

	if( keylen == 0 ) {
		aes_key->keylen_bits = 256;
	}
	else if( keylen == 16 && keylen == 24 && keylen == 32) {
		aes_key->keylen_bits = keylen * 8;
  	} else {
		printf("  . fread of AES Key failed\n");
		return -1;
  	}

	return 0;
}
#endif // USE_PERSISTED_AES_KEY_MATERIAL

int aes_key_gen(aes_key_t *aes_key, size_t keylen_bits, mbedtls_ctr_drbg_context *ctr_drbg_ctx, mbedtls_md_context_t *sha_ctx) {
	size_t keylen;
	int ret = 1;

	/*
	 * Sanity check for Key lengths.
	 */
	if( keylen_bits != 128 || keylen_bits != 192 || keylen_bits != 256 )
		keylen = 32, keylen_bits = 256;
	else
		keylen = keylen_bits / 8;

	/*
	* Generate random data for AES Key and IV
	*/
	print_progress( (char *)"  . Generate random data for AES Key material... ");
	ret = mbedtls_ctr_drbg_random( ctr_drbg_ctx, aes_key->key, keylen );
	if( ret != 0 ) {
		printf("  . mbedtls_ctr_drbg_random() failed, ret = %d\n", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

	print_progress( (char *)"  . Generate random data for AES IV");
	ret = mbedtls_ctr_drbg_random( ctr_drbg_ctx, aes_key->IV, 12 );
	if( ret != 0 ) {
		printf("  . mbedtls_ctr_drbg_random() failed, ret = %d\n", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

#ifndef DDEBUG
	print_buffer( (char *)"  . AES Key before HKDF : ", aes_key->key, keylen );
#endif
	/*
	 * Use HKDF to increase the entropy of random AES Key material.
	 */
	print_progress( (char *)"  . Use HKDF over random AES key to add more entropy...");
	ret = mbedtls_hkdf_extract(sha_ctx->md_info, NULL, 0, aes_key->key, keylen, aes_key->key);
	if( ret != 0 ) {
		printf("  . mbedtls_hkdf_extract() failed, ret = %d\n", ret ), fflush(stdout);
		free(aes_key->key), free(aes_key->IV);
		return ret;
	}
	printf("  OK!\n");

#ifndef DDEBUG
	print_buffer( (char *)"  . AES Key after HKDF :  ", aes_key->key, keylen );
	print_buffer( (char *)"  . AES IV : ", aes_key->IV, 12 );
#endif

	aes_key->keylen_bits = keylen * 8;

	return ret;
}

int do_aes_gcm_encrypt( mbedtls_gcm_context *gcm_ctx, aes_key_t *aes_key, FILE *fin, FILE *fout,
                        off_t filesize )  {

	int ret = 1;
	/*
	 * Append the IV at the beginning of the output.
	 */
	if( fwrite( aes_key->IV, 1, 12, fout ) != 12 ) {
		fprintf( stderr, "fwrite(%d bytes) failed\n", 12 );
		return -1;
	}

	print_progress( (char *)"  . Set GCM Key... ");
	ret = mbedtls_gcm_setkey( gcm_ctx, MBEDTLS_CIPHER_ID_AES, aes_key->key, 256);
	if( ret != 0 ) {
		printf( "  . failed!\n\n\t . mbedtls_gcm_setkey() returned %d", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

	/*
	 * Encrypt and write the ciphertext.
	 */
	print_progress( (char *)"  . Start GCM Encryption...");
	unsigned char buffer[1024];
	mbedtls_gcm_starts( gcm_ctx, MBEDTLS_GCM_ENCRYPT, aes_key->IV, 12, NULL, 0);

	for( off_t offset = 0; offset < filesize; offset += 16 ) {
		off_t n = ( filesize - offset > 16 ) ? 16 : (off_t)( filesize - offset );

		if( fread( buffer, 1, n, fin ) != (size_t) n ) {
			printf("  . fread(%lld bytes) failed\n", n );
			return -1;
		}

		ret = mbedtls_gcm_update( gcm_ctx, n, buffer, buffer);
		if( ret != 0 ) {
			printf( "  . failed!\n\n\t . mbedtls_gcm_update() returned %d", ret), fflush(stdout);
			return ret;
		}

		if( fwrite( buffer, 1, n, fout ) != (size_t) n ) {
			printf( "  . fwrite(%lld bytes) failed\n", n );
			return -1;
		}
	}
	printf("  OK!\n");

	/*
	 * Finally write the HMAC.
	 */
	print_progress( (char *)"  . Finish GCM Encryption...");
	ret = mbedtls_gcm_finish( gcm_ctx, buffer, 16);
	if( ret != 0 ) {
		printf( "  . failed!\n\n\t . mbedtls_gcm_finish() returned %d", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

	if( fwrite( buffer, 1, 16, fout ) != 16 ) {
		mbedtls_fprintf( stderr, "fwrite(%d bytes) failed\n", 16 );
		return -1;
	}

	return 0;
}

int do_aes_gcm_decrypt( mbedtls_gcm_context *gcm_ctx, aes_key_t *aes_key, FILE *fin, FILE *fout,
                        off_t filesize )  {

	int ret = 1;
	/*
	 * The encrypted file must be structured as follows:
	 *
	 *	00 .. 11			Initialization Vector
	 *	12 .. 28			AES Encrypted Block #1
	 *	..
	 *  filesize - 17 .. filesize -1	AES-GCM Hash (ciphertext)
	 */
	if( filesize < 28 ) {
		printf( "  . Failed!\n\n\t . File too short to be encrypted.\n" );
		return -1;
	}

	/*
	* Subtract the IV + GCM Digest length.
	*/
	filesize -= ( 12 + 16 );

	/*
	* Read the IV and original filesize modulo 16.
	*/
	if( fread( aes_key->IV, 1, 12, fin ) != 12 ) {
		printf( "  . Failed!\n\n\t . fread(12 bytes) of IV failed\n" );
		return -1;
	}

	print_progress( (char *)"  . Set GCM Key... ");
	ret = mbedtls_gcm_setkey( gcm_ctx, MBEDTLS_CIPHER_ID_AES, aes_key->key, 256);
	if( ret != 0 ) {
		printf( "  . Failed!\n\n\t . mbedtls_gcm_setkey() returned %d", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

	/*
	 * Encrypt and write the ciphertext.
	 */
	print_progress( (char *)"  . Start GCM Decryption...");
	unsigned char out_buff[1024];
	unsigned char in_buff[32];

	ret = mbedtls_gcm_starts( gcm_ctx, MBEDTLS_GCM_DECRYPT, aes_key->IV, 12, NULL, 0);
	if( ret != 0 ) {
		printf( "  . Failed!\n\n\t . mbedtls_gcm_starts() returned %d", ret), fflush(stdout);
		return ret;
	}

	for( off_t offset = 0; offset < filesize; offset += 16 ) {
		off_t n = ( filesize - offset > 16 ) ? 16 : (off_t)( filesize - offset );

		if( fread( in_buff, 1, n, fin ) != (size_t) n ) {
			printf("  . Failed!\n\n\t . fread(%lld bytes) failed\n", n );
			return -1;
		}

		ret = mbedtls_gcm_update( gcm_ctx, n, in_buff, out_buff);
		if( ret != 0 ) {
			printf( "  . Failed!\n\n\t . mbedtls_gcm_update() returned %d", ret), fflush(stdout);
			return ret;
		}

		if( fwrite( out_buff, 1, n, fout ) != (size_t) n ) {
			printf( "  . Failed!\n\n\t . fwrite(%lld bytes) failed\n", n );
			return -1;
		}
	}
	printf("  OK!\n");

	/*
	 * Finally process the HMAC.
	 */
	if( fread( in_buff, 1, 16, fin ) != 16 ) {
		printf( "  . Failed!\n\n\t . fread(%d bytes) failed\n", 16 );
		return -1;
	}

	print_progress( (char *)"  . Finish GCM Decryption...");
	ret = mbedtls_gcm_finish( gcm_ctx, out_buff, 16);
	if( ret != 0 ) {
		printf( "   . Failed!\n\n\t . mbedtls_gcm_finish() returned %d", ret), fflush(stdout);
		return ret;
	}
	printf("  OK!\n");

	/* Use constant-time buffer comparison */
	unsigned char diff = 0;
	for( off_t i = 0; i < 16; i++ ) {
		diff |= in_buff[i] ^ out_buff[i];
		if( diff ) break;
	}

	if( diff != 0 ) {
		printf( "  . Failed!\n\n\t . HMAC check failed: wrong key, or file corrupted.\n" );
		return diff;
	}

	return 0;
}

int main( int argc, char *argv[] ) {
	int ret = 1;

	aes_key_t aes_key;
	mbedtls_entropy_context entropy_ctx;
	mbedtls_ctr_drbg_context ctr_drbg_ctx;
	mbedtls_md_context_t sha_ctx;
	mbedtls_gcm_context gcm_ctx;

	print_progress( (char *)"Initialize entropy, ctr_drbg, sha and gcm contexts...");
	aes_key_init( &aes_key, 32, 12 );
	mbedtls_entropy_init( &entropy_ctx );
	mbedtls_ctr_drbg_init( &ctr_drbg_ctx );
	mbedtls_md_init( &sha_ctx );
	mbedtls_gcm_init( &gcm_ctx );
	printf("  OK!\n");

	off_t filesize;

	unsigned char encrypted_aes_key[32];

	if( argc < 3) {
		printf( USAGE, argv[0] );
		goto exit;
	}

	int mode = atoi( argv[1] );

	print_progress( (char *)"  . Do file related pre-processing..." );
	FILE *fin= NULL, *fout = NULL;
	if( ( fin = fopen( argv[2], "rb" ) ) == NULL ) {
		printf("  . Failed!\n\n\t . fopen(%s,rb) failed\n", argv[2] );
		goto exit;
	}

	if( ( fout = fopen( argv[3], "wb+" ) ) == NULL ) {
		printf("  . Failed!\n\n\t . fopen(%s,wb+) failed\n", argv[3] );
		goto exit;
	}

	if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 ) {
		printf("  . Failed!\n\n\t . lseek(fin, 0, SEEK_END) failed...\n");
		goto exit;
	}

	if( fseek( fin, 0, SEEK_SET ) < 0 ) {
		printf("  . Failed!\n\n\t . lseek(fin, 0, SEEK_SET) failed...\n");
		goto exit;
	}

	printf("  OK!\n");
	printf("  . Input filesize = %lld \n", filesize);

	/*
	 * Seed the random number generator.
	 */
	print_progress( (char *)"  . Seeding the random number generator..." );
	ret = mbedtls_ctr_drbg_seed( &ctr_drbg_ctx, mbedtls_entropy_func, &entropy_ctx, NULL, 0);
	                             // (const unsigned char *) "RANDOM_GEN", 10 );
	if( ret != 0 ) {
		printf( "  . Failed!\n\n\t . mbedtls_ctr_drbg_seed() returned %d", ret), fflush(stdout);
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
		printf( "  . Failed!\n\n\t . mbedtls_md_setup() returned -0x%04x\n", -ret );
		return ret;
	}
	printf("  OK!\n");

	if( mode == MODE_ENCRYPT ) {
		/*
		 * Initialize the AES Key and IV.
		 */
		print_progress( (char *)"  . Get the AES KEY and IV... STARTED!");

#ifdef USE_PERSISTED_AES_KEY_MATERIAL

		print_progress( (char *)"  . Read previously persisted ephemeral AES Key and IV... " );
		ret = read_aes_key_material( &aes_key );
		if( ret != 0 ) {
			goto exit;
		}
		printf("  OK!\n");

#else // USE_PERSISTED_AES_KEY_MATERIAL

		print_progress( (char *)"  . Generate ephemeral AES Key and IV... STARTED!\n" );
		ret = aes_key_gen( &aes_key, 256, &ctr_drbg_ctx, &sha_ctx );
		if( ret != 0 ) {
			goto exit;
		}
		print_progress( (char *)"  . Generate ephemeral AES Key and IV... OK!\n" );

#ifdef PERSIST_AES_KEY_MATERIAL

		print_progress( (char *)"  . Write AES Key material to persistent storage..." );
		ret = persist_aes_key_material( &aes_key, (char *)"aes_key.bin", (char *)"aes_iv.bin");
		if( ret != 0 ) {
			printf("  . Failed\n\n\t . persist_aes_key_material() returned %d", ret);
		}
		printf("  OK!\n");

#endif // PERSIST_AES_KEY_MATERIAL
#endif // USE_PERSISTED_AES_KEY_MATERIAL

		print_buffer( (char *)"  . Final AES Key: ", aes_key.key, aes_key.keylen_bits/8 );
		print_buffer( (char *)"  . Final AES IV : ", aes_key.IV, 12 );

		printf( "  . Get the AES KEY and IV... OK!");

		print_progress( (char *)"  . Encrypt AES key to Server... STARTED!\n");
#if 1
		ret = ec_operation( aes_key.key, &encrypted_aes_key[0], MODE_ENCRYPT, &ctr_drbg_ctx, &sha_ctx );
#else
		ret = enc_key_to_server( aes_key.key, &encrypted_aes_key[0], &ctr_drbg_ctx, &sha_ctx );
#endif
		if( ret != 0 ) {
			printf("  . Encrypt AES key to Server... Failed\n  . enc_key_to_server() return %d", ret );
			goto exit;
		}
		print_progress( (char *)"  . Encrypt AES key to Server... OK!\n");
		/*
		 * Write encrypted AES Key to output file.
		 */
		if( fwrite( &encrypted_aes_key[0], 1, 32, fout ) != 32 ) {
			fprintf( stderr, "fwrite(%d bytes) of Encrypted AES key failed\n", 32 );
			goto exit;
		}
		/*
		 * Encrypt the payload data using AES GCM
		 */
		print_progress( (char *)"  . Encrypt the payload using AES GCM... STARTED!\n");
		ret = do_aes_gcm_encrypt ( &gcm_ctx, &aes_key, fin, fout, filesize);
		if( ret != 0 ) {
			printf("  . Failed!\n\n\t . Encrypt the payload using AES GCM... FAILED!\n  . do_aes_gcm_encrypt() returned %d", ret), fflush(stdout);
			goto exit;
		}
		print_progress( (char *)"  . Encrypt the payload using AES GCM... OK!\n");
	}
	else if ( mode == MODE_DECRYPT ) {
		/*
		 * Decrypt the payload data using AES GCM
		 */
		print_progress( (char *)"  . Read encrypted AES Key from file... ");
		ret = read_fbuffer( NULL, fin, &encrypted_aes_key[0], 32);
		if( ret != 0) {
			printf("  . failed to read 32 bytes\n");
			goto exit;
		}
		printf("  OK!\n");

#ifdef DEBUG
		print_buffer( (char *)"  . Encrypted AES Key: ", &encrypted_aes_key[0], 32);
#endif

		print_progress( (char *)"  .Decrypt the AES Key at server... STARTED!\n");
#if 1
		ret = ec_operation( &encrypted_aes_key[0], aes_key.key, MODE_DECRYPT, &ctr_drbg_ctx, &sha_ctx );
#else
		ret = dec_aes_at_server( &encrypted_aes_key[0], aes_key.key, &ctr_drbg_ctx, &sha_ctx );
#endif
		if( ret != 0 ) {
			printf("  . Encrypt AES key to Server... Failed\n  . enc_key_to_server() return %d", ret );
			goto exit;
		}
		print_progress( (char *)"  . Decrypt AES key to Server... OK!\n");

		print_progress( (char *)"  . Decrypt the payload using AES GCM... STARTED!\n");

		ret = do_aes_gcm_decrypt ( &gcm_ctx, &aes_key, fin, fout, filesize - 32);

		if( ret != 0 ) {
			printf("  . Failed!\n\n\t . Decrypt the payload using AES GCM... FAILED!\n  . do_aes_gcm_decrypt() returned %d", ret), fflush(stdout);
			goto exit;
		}
		print_progress( (char *)"  . Decrypt the payload using AES GCM... OK!\n");
	}

exit:
	print_progress( (char *)"Free entropy, ctr_drbg, sha, gcm and aes_key contexts...");
	mbedtls_ctr_drbg_free( &ctr_drbg_ctx );
	mbedtls_entropy_free( &entropy_ctx );
	mbedtls_gcm_free( &gcm_ctx );
	aes_free( &aes_key );
	printf("  OK!\n");

	return ret;
}
