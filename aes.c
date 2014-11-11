/*
 * Demo on how to use /dev/crypto device for ciphering.
 *
 * Placed under public domain.
 *
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>
#include "aes.h"

#define	KEY_SIZE	16

int aes_padding_size(char *msg){
 	int msg_size = strlen(msg);
	return (msg_size+(AES_BLOCK_SIZE-(msg_size%AES_BLOCK_SIZE)));
}

int aes_ctx_init(struct cryptodev_ctx* ctx, int cfd, const uint8_t *key, unsigned int key_size)
{
#ifdef CIOCGSESSINFO
	struct session_info_op siop;
#endif
	printf ("Key %s, Size %d\n",key, key_size);

	memset(ctx, 0, sizeof(*ctx));
	ctx->cfd = cfd;

	ctx->sess.cipher = CRYPTO_AES_CBC;
	ctx->sess.keylen = key_size;
	ctx->sess.key = (void*)key;
	if (ioctl(ctx->cfd, CIOCGSESSION, &ctx->sess)) {
		perror("ioctl(CIOCGSESSION)");
		return -1;
	}

#ifdef CIOCGSESSINFO
	memset(&siop, 0, sizeof(siop));

	siop.ses = ctx->sess.ses;
	if (ioctl(ctx->cfd, CIOCGSESSINFO, &siop)) {
		perror("ioctl(CIOCGSESSINFO)");
		return -1;
	}
	printf("Got %s with driver %s\n",
			siop.cipher_info.cra_name, siop.cipher_info.cra_driver_name);
	if (!(siop.flags & SIOP_FLAG_KERNEL_DRIVER_ONLY)) {
		printf("Note: This is not an accelerated cipher\n");
	}
	/*printf("Alignmask is %x\n", (unsigned int)siop.alignmask); */
	ctx->alignmask = siop.alignmask;
#endif
	return 0;
}

void aes_ctx_deinit(struct cryptodev_ctx* ctx) 
{
	if (ioctl(ctx->cfd, CIOCFSESSION, &ctx->sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
	}
}

int
aes_encrypt(struct cryptodev_ctx* ctx, const void* iv, const void* plaintext, void* ciphertext, size_t size)
{
	struct crypt_op cryp;
	void* p;
	
	/* check plaintext and ciphertext alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)plaintext + ctx->alignmask) & ~ctx->alignmask);
		if (plaintext != p) {
			fprintf(stderr, "plaintext is not aligned\n");
			return -1;
		}

		p = (void*)(((unsigned long)ciphertext + ctx->alignmask) & ~ctx->alignmask);
		if (ciphertext != p) {
			fprintf(stderr, "ciphertext is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)plaintext;
	cryp.dst = ciphertext;
	cryp.iv = (void*)iv;
	cryp.op = COP_ENCRYPT;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	return 0;
}

int
aes_decrypt(struct cryptodev_ctx* ctx, const void* iv, const void* ciphertext, void* plaintext, size_t size)
{
	struct crypt_op cryp;
	void* p;
	
	/* check plaintext and ciphertext alignment */
	if (ctx->alignmask) {
		p = (void*)(((unsigned long)plaintext + ctx->alignmask) & ~ctx->alignmask);
		if (plaintext != p) {
			fprintf(stderr, "plaintext is not aligned\n");
			return -1;
		}

		p = (void*)(((unsigned long)ciphertext + ctx->alignmask) & ~ctx->alignmask);
		if (ciphertext != p) {
			fprintf(stderr, "ciphertext is not aligned\n");
			return -1;
		}
	}

	memset(&cryp, 0, sizeof(cryp));

	/* Encrypt data.in to data.encrypted */
	cryp.ses = ctx->sess.ses;
	cryp.len = size;
	cryp.src = (void*)ciphertext;
	cryp.dst = plaintext;
	cryp.iv = (void*)iv;
	cryp.op = COP_DECRYPT;
	if (ioctl(ctx->cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return -1;
	}

	return 0;
}

int test_encrypt(int cfd,char *message,char *key){
	int i=0;
        struct cryptodev_ctx ctx;
        char plaintext_raw[AES_BLOCK_SIZE + 63], *plaintext, *encrypttext;
        char iv[AES_BLOCK_SIZE];       

	aes_ctx_init(&ctx, cfd, key, strlen(key));	
		
	memset(iv, 0x0, sizeof(iv));

	if (ctx.alignmask) {
		plaintext = (char *)(((unsigned long)plaintext_raw + ctx.alignmask) & ~ctx.alignmask);
	} else {
		plaintext = plaintext_raw;
	}
	memset(plaintext,'{',aes_padding_size(message));
	memcpy(plaintext, message, strlen(message));
	aes_encrypt(&ctx, iv, plaintext, plaintext, strlen(plaintext));
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%02x ", plaintext[i]);
	}

	aes_ctx_deinit(&ctx);

	aes_ctx_init(&ctx, cfd, key, strlen(key));	
	
	memset(iv, 0x0, sizeof(iv));

	if (ctx.alignmask) {
		encrypttext = (char *)(((unsigned long)plaintext_raw + ctx.alignmask) & ~ctx.alignmask);
	} else {
		encrypttext = plaintext_raw;
	}

	memcpy(encrypttext, plaintext, strlen(plaintext));
	aes_decrypt(&ctx, iv, encrypttext, encrypttext, strlen(encrypttext));
	for (i = 0; i < AES_BLOCK_SIZE; i++) {
		printf("%02x ", encrypttext[i]);
	}

	aes_ctx_deinit(&ctx);


}

int
main(int argc, char **argv)
{
	int cfd = -1, i=0;
	struct cryptodev_ctx ctx;
	char plaintext2_raw[AES_BLOCK_SIZE + 63], *plaintext2;
	char iv2[AES_BLOCK_SIZE];	

	if (argc<3)
	    return -1;

	/* Open the crypto device */
	cfd = open("/dev/crypto", O_RDWR, 0);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Set close-on-exec (not really neede here) */
	if (fcntl(cfd, F_SETFD, 1) == -1) {
		perror("fcntl(F_SETFD)");
		return 1;
	}
	test_encrypt(cfd,argv[1],argv[2]);
	/* Close the original descriptor */
	if (close(cfd)) {
		perror("close(cfd)");
		return 1;
	}

	return 0;
}

