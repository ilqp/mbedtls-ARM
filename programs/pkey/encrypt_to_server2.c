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

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  %s <mode> <input filename> <output filename>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n"

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

	unsigned char *shared_aes_key = (unsigned char*) calloc(32,1);

	ret = mbedtls_mpi_write_binary( &enc_ctx.z, shared_aes_key, 32 );
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
	ret = mbedtls_mpi_read_binary( &enc_ctx.z, shared_aes_key, 32 );
	if( ret != 0 ) {
		printf( " Failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
		goto cleanup;
	}
	printf("===========================================================================\n");
	mbedtls_mpi_write_file("shared_aes_key: ", &enc_ctx.z, 16, NULL);
	printf("Length of shared_aes_key in bits: %zu\n", mbedtls_mpi_bitlen(&enc_ctx.z));
#endif

	print_progress( (char *)"  . Encrypt the Ephemeral AES key with shared AES Key.  OK!\n");
	for( int i = 0; i < 32; i++ )
		in_aes_key[i] = (unsigned char)( in_aes_key[i] ^ shared_aes_key[i] );

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
			fprintf( stderr, "  . fwrite(%d bytes) failed\n", 16 );
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
	if( fread( in_buff, 1, 16, fout ) != 16 ) {
		printf( "  . Failed!\n\n\t . fread(%d bytes) failed\n", 16 );
		return -1;
	}

	print_progress( (char *)"  . Finish GCM Decryption...");
	ret = mbedtls_gcm_finish( gcm_ctx, out_buff, 16);
	if( ret != 0 ) {
		printf( "   . Failed!\n\n\t . mbedtls_gcm_finish() returned %d", ret), fflush(stdout);
		return ret;
	}

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

	mbedtls_entropy_init( &entropy_ctx );
	mbedtls_ctr_drbg_init( &ctr_drbg_ctx );
	mbedtls_md_init( &sha_ctx );
	mbedtls_gcm_init( &gcm_ctx );

	off_t filesize;

	if( argc < 3) {
		printf( USAGE, argv[0] );
		goto exit;
	}

	int mode = atoi( argv[1] );

	print_progress( (char *)"  . Do file related pre-processing..." );

	FILE *fin= NULL, *fout = NULL;
	if( ( fin = fopen( argv[2], "rb" ) ) == NULL ) {
		printf("  . fopen(%s,rb) failed\n", argv[2] );
		goto exit;
	}

	if( ( fout = fopen( argv[3], "wb+" ) ) == NULL ) {
		printf("  . fopen(%s,wb+) failed\n", argv[3] );
		goto exit;
	}

	if( ( filesize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 ) {
		printf("  . lseek(fin, 0, SEEK_END) failed...\n");
		goto exit;
	}

	if( fseek( fin, 0, SEEK_SET ) < 0 ) {
		printf("  . lseek(fin, 0, SEEK_SET) failed...\n");
		goto exit;
	}
	printf("  OK!\n");

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

	if( mode == MODE_ENCRYPT ) {
#if 1
		print_progress( (char *)"  . Start Encryption to Server... STARTED!\n");
		ret = enc_to_server( aes_key.key, fout, &ctr_drbg_ctx, &sha_ctx );
		if( ret != 0 ) {
			printf("  . Start Encryption to Server... Failed\n  . enc_to_server() return %d", ret );
			goto exit;
		}
		printf("  OK!\n");
#endif
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
		print_progress( (char *)"  . Decrypt the payload using AES GCM... STARTED!\n");
		ret = do_aes_gcm_decrypt ( &gcm_ctx, &aes_key, fin, fout, filesize);
		if( ret != 0 ) {
			printf("  . Failed!\n\n\t . Decrypt the payload using AES GCM... FAILED!\n  . do_aes_gcm_decrypt() returned %d", ret), fflush(stdout);
			goto exit;
		}
		print_progress( (char *)"  . Decrypt the payload using AES GCM... OK!\n");
	}

exit:
	mbedtls_ctr_drbg_free( &ctr_drbg_ctx );
	mbedtls_entropy_free( &entropy_ctx );
	mbedtls_gcm_free( &gcm_ctx );
	aes_free( &aes_key );
	return ret;
}
