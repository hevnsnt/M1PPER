/* See COPYING.txt for license details. */

/*
*
*  m1_wifi_cred.c
*
*  Encrypted WiFi credential storage on SD card.
*  Uses AES-256-CBC encryption from m1_crypto for secure storage.
*
* M1 Project
*
*/

/*************************** I N C L U D E S **********************************/

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "m1_wifi_cred.h"
#include "m1_crypto.h"
#include "ff.h"
#include "stm32h5xx_hal.h"
#include "m1_log_debug.h"

/*************************** D E F I N E S ************************************/

/*
 * File format (binary):
 *   [magic (4 bytes)] [version (1 byte)] [record_count (1 byte)]
 *   [record 0] [record 1] ... [record N-1]
 *
 * Each record:
 *   [encrypted_len (4 bytes, little-endian)]
 *   [encrypted_data (variable length)]
 *
 * Encrypted data format (before encryption):
 *   [SSID\0] [PASSWORD\0]
 *   (two null-terminated strings concatenated)
 *
 * After encryption:
 *   [IV (16 bytes)] [ciphertext with PKCS7 padding]
 */

#define WIFI_CRED_FILE_MAGIC       0x57494649  /* "WIFI" in little-endian */
/* File format version:
 *   v1 = AES key derived from UID + KEY_DERIVE_MAGIC (legacy; vulnerable
 *        to firmware-binary recovery)
 *   v2 = AES key written ONCE to FLASH_OTP from the on-chip TRNG; not
 *        recoverable from the firmware binary alone (Phase 5.10).
 *
 * Reader accepts both. Writer always emits v2 once the persistent key
 * has been successfully bootstrapped. */
#define WIFI_CRED_FILE_VERSION_V1  1
#define WIFI_CRED_FILE_VERSION_V2  2
#define WIFI_CRED_FILE_VERSION     WIFI_CRED_FILE_VERSION_V2
#define WIFI_CRED_HEADER_SIZE      6  /* magic(4) + version(1) + count(1) */

/*-----------------------------------------------------------------------*
 *  Persistent device key — Phase 5.10
 *
 *  We store a 32-byte AES key in the STM32H5 OTP area (FLASH_OTP_BASE,
 *  2 KB at 0x08FFF000). OTP can be programmed once and is never erasable,
 *  giving us a per-device secret that:
 *    - is not derivable from any single firmware binary,
 *    - survives firmware updates (the writer never touches OTP),
 *    - is not exposable through the public PWR/RDP option-byte sequence.
 *
 *  Layout (3 quadwords = 48 bytes; rest of OTP left untouched):
 *    +0x00  magic            uint32_t   M1_WIFI_KEY_MAGIC
 *    +0x04  version          uint8_t    1
 *    +0x05  reserved         uint8_t[11] zero
 *    +0x10  key (32 bytes — two quadwords)
 *    +0x30  end
 *
 *  An erased quadword reads as 0xFFFFFFFF×4. We treat that as "not yet
 *  written" and program the OTP from the TRNG. Any other non-magic
 *  pattern means another firmware variant has used the same OTP slot —
 *  in that case we MUST refuse to write (OTP is single-write) and fall
 *  back to legacy v1 encryption. */
#define M1_WIFI_KEY_OTP_OFFSET     0u
#define M1_WIFI_KEY_OTP_ADDR       (FLASH_OTP_BASE + M1_WIFI_KEY_OTP_OFFSET)
#define M1_WIFI_KEY_MAGIC          0x4D314B4DUL    /* "M1KM" */

/* Maximum plaintext size for a single credential:
 * SSID (33 bytes max including null) + Password (65 bytes max including null) = 98 bytes
 * After encryption with PKCS7: need room for IV(16) + padded(112) = 128 bytes max */
#define WIFI_CRED_PLAIN_MAX_SIZE   (WIFI_CRED_SSID_MAX_LEN + WIFI_CRED_PASS_MAX_LEN)
#define WIFI_CRED_ENC_MAX_SIZE     (M1_CRYPTO_IV_SIZE + ((WIFI_CRED_PLAIN_MAX_SIZE / M1_CRYPTO_AES_BLOCK_SIZE) + 1) * M1_CRYPTO_AES_BLOCK_SIZE)

/* Static work buffer for encryption/decryption (no heap!) */
#define WIFI_CRED_WORK_BUF_SIZE    256

//************************** S T R U C T U R E S *******************************

//****************************** V A R I A B L E S *****************************/

static uint8_t s_work_buf[WIFI_CRED_WORK_BUF_SIZE];

/* In-memory credential cache for save/delete operations */
static wifi_credential_t s_cred_cache[WIFI_CRED_MAX_STORED];
static uint8_t s_cred_cache_count;

/* Cache the persistent key once per boot. NULL until the first call to
 * persistent_key_get(). The key is 32 bytes; we keep it in BSS (cleared
 * on every reboot if we miss the load) and rely on lazy load. */
static uint8_t s_persistent_key[M1_CRYPTO_AES_KEY_SIZE];
static enum {
	KEYSTATE_UNKNOWN = 0,   /* not yet loaded */
	KEYSTATE_PRESENT,       /* OTP held the key OR we just wrote it */
	KEYSTATE_OTP_USED,      /* OTP has a different magic — fall back to legacy */
	KEYSTATE_FAILED,        /* TRNG/OTP write failed; legacy fallback */
} s_persistent_key_state = KEYSTATE_UNKNOWN;

/********************* F U N C T I O N   P R O T O T Y P E S ******************/

static bool write_all_credentials(void);
static bool ensure_system_dir(void);
static bool read_file_header(FIL *file, uint8_t *record_count, uint8_t *version_out);
static bool write_file_header(FIL *file, uint8_t record_count);
static bool read_record(FIL *file, wifi_credential_t *cred, uint8_t version);
static bool write_record(FIL *file, const wifi_credential_t *cred);
static bool persistent_key_get(uint8_t key_out[M1_CRYPTO_AES_KEY_SIZE]);

/*************** F U N C T I O N   I M P L E M E N T A T I O N ****************/



/*============================================================================*/
/*
 * Ensure 0:/System/ directory exists
 */
/*============================================================================*/
static bool ensure_system_dir(void)
{
	FILINFO fno;
	FRESULT res;

	res = f_stat("0:/System", &fno);
	if (res != FR_OK)
	{
		res = f_mkdir("0:/System");
		if (res != FR_OK)
			return false;
	}
	return true;
} // static bool ensure_system_dir(void)



/*============================================================================*/
/*
 * Bootstrap or load the per-device AES key from the STM32H5 OTP area.
 *
 *  Phase 5.10 (audit 06-security #3): replaces the legacy
 *  m1_crypto_derive_key() path which mixed UID with a single global magic
 *  constant. With the legacy scheme, anyone holding the firmware binary
 *  could decompile, find the constant, read any device's UID over SWD,
 *  and reproduce the key for ALL units. The OTP-stored key is unique to
 *  each device (TRNG-derived) and cannot be predicted from the binary.
 *
 *  Returns true on success and fills key_out. Returns false if the OTP
 *  is in an unrecognised state OR if the TRNG was unavailable when we
 *  needed to mint a new key — caller must fall back to legacy v1 path.
 *
 *  Concurrency: this function is intended to be called from a single
 *  task context (the WiFi-credential menu). We do not lock around the
 *  static cache; the runtime currently never invokes credential reads
 *  from two tasks at once.
 */
/*============================================================================*/
static bool persistent_key_get(uint8_t key_out[M1_CRYPTO_AES_KEY_SIZE])
{
	if (s_persistent_key_state == KEYSTATE_PRESENT)
	{
		memcpy(key_out, s_persistent_key, M1_CRYPTO_AES_KEY_SIZE);
		return true;
	}
	if (s_persistent_key_state == KEYSTATE_OTP_USED ||
	    s_persistent_key_state == KEYSTATE_FAILED)
	{
		/* Already determined we can't use OTP. Don't keep retrying. */
		return false;
	}

	/* First call this boot — read the OTP header. */
	const volatile uint32_t *otp = (const volatile uint32_t *)M1_WIFI_KEY_OTP_ADDR;
	uint32_t magic   = otp[0];
	uint32_t version = otp[1] & 0xFFu;

	if (magic == 0xFFFFFFFFu)
	{
		/* Erased quadword. We can program OTP. */
		uint8_t fresh_key[M1_CRYPTO_AES_KEY_SIZE];
		if (!m1_crypto_trng_fill(fresh_key, sizeof(fresh_key)))
		{
			M1_LOG_E("WIFICRED",
			         "TRNG failed during persistent-key mint; falling back to legacy");
			s_persistent_key_state = KEYSTATE_FAILED;
			return false;
		}

		/* Build the OTP image: 3 quadwords (48 bytes) */
		uint8_t otp_image[48];
		memset(otp_image, 0xFF, sizeof(otp_image));
		otp_image[0]  = (uint8_t)(M1_WIFI_KEY_MAGIC & 0xFF);
		otp_image[1]  = (uint8_t)((M1_WIFI_KEY_MAGIC >> 8)  & 0xFF);
		otp_image[2]  = (uint8_t)((M1_WIFI_KEY_MAGIC >> 16) & 0xFF);
		otp_image[3]  = (uint8_t)((M1_WIFI_KEY_MAGIC >> 24) & 0xFF);
		otp_image[4]  = 1;  /* version */
		/* otp_image[5..15] reserved 0xFF */
		memcpy(&otp_image[16], fresh_key, M1_CRYPTO_AES_KEY_SIZE);

		/* Program in 16-byte quadwords. HAL_FLASH_Program with
		 * FLASH_TYPEPROGRAM_QUADWORD writes a 16-byte aligned chunk. */
		HAL_FLASH_Unlock();
		bool wrote_ok = true;
		for (uint32_t i = 0; i < 48; i += 16)
		{
			if (HAL_FLASH_Program(FLASH_TYPEPROGRAM_QUADWORD,
			                      M1_WIFI_KEY_OTP_ADDR + i,
			                      (uint32_t)(uintptr_t)&otp_image[i]) != HAL_OK)
			{
				wrote_ok = false;
				break;
			}
		}
		HAL_FLASH_Lock();

		/* Wipe stack copy of fresh_key in either path. */
		memset(otp_image, 0, sizeof(otp_image));

		if (!wrote_ok)
		{
			M1_LOG_E("WIFICRED", "OTP program failed; falling back to legacy");
			memset(fresh_key, 0, sizeof(fresh_key));
			s_persistent_key_state = KEYSTATE_FAILED;
			return false;
		}

		/* Verify by reading back. */
		if (otp[0] != M1_WIFI_KEY_MAGIC)
		{
			M1_LOG_E("WIFICRED", "OTP write verify failed (magic=0x%08lX)",
			         (unsigned long)otp[0]);
			memset(fresh_key, 0, sizeof(fresh_key));
			s_persistent_key_state = KEYSTATE_FAILED;
			return false;
		}

		memcpy(s_persistent_key, fresh_key, sizeof(s_persistent_key));
		memset(fresh_key, 0, sizeof(fresh_key));
		s_persistent_key_state = KEYSTATE_PRESENT;
		memcpy(key_out, s_persistent_key, M1_CRYPTO_AES_KEY_SIZE);
		M1_LOG_I("WIFICRED", "Persistent key minted to OTP (first boot)");
		return true;
	}

	if (magic == M1_WIFI_KEY_MAGIC && version == 1u)
	{
		/* Already programmed on a prior boot. */
		const volatile uint8_t *otp_bytes =
		    (const volatile uint8_t *)M1_WIFI_KEY_OTP_ADDR;
		for (uint32_t i = 0; i < M1_CRYPTO_AES_KEY_SIZE; i++)
			s_persistent_key[i] = otp_bytes[16 + i];
		s_persistent_key_state = KEYSTATE_PRESENT;
		memcpy(key_out, s_persistent_key, M1_CRYPTO_AES_KEY_SIZE);
		return true;
	}

	/* Some other firmware previously wrote a different magic into this
	 * OTP slot. We cannot rewrite it. Mark as unusable so we stop
	 * checking, and force callers to fall back to legacy. */
	M1_LOG_W("WIFICRED",
	         "OTP slot already used by a different firmware (magic=0x%08lX) — using legacy key",
	         (unsigned long)magic);
	s_persistent_key_state = KEYSTATE_OTP_USED;
	return false;
}


/*============================================================================*/
/*
 * Read and validate the file header
 */
/*============================================================================*/
static bool read_file_header(FIL *file, uint8_t *record_count, uint8_t *version_out)
{
	uint8_t header[WIFI_CRED_HEADER_SIZE];
	UINT br;
	FRESULT res;
	uint32_t magic;

	res = f_read(file, header, WIFI_CRED_HEADER_SIZE, &br);
	if (res != FR_OK || br != WIFI_CRED_HEADER_SIZE)
		return false;

	/* Check magic */
	magic = (uint32_t)header[0] |
	        ((uint32_t)header[1] << 8) |
	        ((uint32_t)header[2] << 16) |
	        ((uint32_t)header[3] << 24);

	if (magic != WIFI_CRED_FILE_MAGIC)
		return false;

	/* Accept v1 (legacy UID-derived key) and v2 (TRNG/OTP key). The
	 * caller will pass the version through to read_record() so that
	 * each record decrypts with the right key. */
	if (header[4] != WIFI_CRED_FILE_VERSION_V1 &&
	    header[4] != WIFI_CRED_FILE_VERSION_V2)
		return false;
	if (version_out)
		*version_out = header[4];

	*record_count = header[5];
	if (*record_count > WIFI_CRED_MAX_STORED)
		*record_count = WIFI_CRED_MAX_STORED;

	return true;
} // static bool read_file_header(...)



/*============================================================================*/
/*
 * Write the file header
 */
/*============================================================================*/
static bool write_file_header(FIL *file, uint8_t record_count)
{
	uint8_t header[WIFI_CRED_HEADER_SIZE];
	UINT bw;
	FRESULT res;

	header[0] = (uint8_t)(WIFI_CRED_FILE_MAGIC & 0xFF);
	header[1] = (uint8_t)((WIFI_CRED_FILE_MAGIC >> 8) & 0xFF);
	header[2] = (uint8_t)((WIFI_CRED_FILE_MAGIC >> 16) & 0xFF);
	header[3] = (uint8_t)((WIFI_CRED_FILE_MAGIC >> 24) & 0xFF);

	/* Emit v2 if the persistent OTP key is usable, otherwise downgrade
	 * to v1 so a future read can still decrypt with the legacy key.
	 * persistent_key_get() is idempotent and cached. */
	uint8_t probe_key[M1_CRYPTO_AES_KEY_SIZE];
	if (persistent_key_get(probe_key))
		header[4] = WIFI_CRED_FILE_VERSION_V2;
	else
		header[4] = WIFI_CRED_FILE_VERSION_V1;
	memset(probe_key, 0, sizeof(probe_key));

	header[5] = record_count;

	res = f_write(file, header, WIFI_CRED_HEADER_SIZE, &bw);
	return (res == FR_OK && bw == WIFI_CRED_HEADER_SIZE);
} // static bool write_file_header(...)



/*============================================================================*/
/*
 * Read a single encrypted record from file and decrypt it.
 *
 *   version == V1 -> legacy UID-derived key (m1_crypto_derive_key path)
 *   version == V2 -> TRNG-derived persistent key from OTP
 *
 * Both flow through m1_crypto_decrypt_with_key with an explicitly loaded
 * key so the choice is local to read_record() and doesn't leak into the
 * crypto module.
 */
/*============================================================================*/
static bool read_record(FIL *file, wifi_credential_t *cred, uint8_t version)
{
	uint8_t len_buf[4];
	uint32_t enc_len;
	uint32_t plain_len;
	UINT br;
	FRESULT res;
	const char *ssid_ptr;
	const char *pass_ptr;
	size_t ssid_len;
	uint8_t key[M1_CRYPTO_AES_KEY_SIZE];

	memset(cred, 0, sizeof(wifi_credential_t));

	/* Read encrypted data length (4 bytes, little-endian) */
	res = f_read(file, len_buf, 4, &br);
	if (res != FR_OK || br != 4)
		return false;

	enc_len = (uint32_t)len_buf[0] |
	          ((uint32_t)len_buf[1] << 8) |
	          ((uint32_t)len_buf[2] << 16) |
	          ((uint32_t)len_buf[3] << 24);

	if (enc_len == 0 || enc_len > WIFI_CRED_WORK_BUF_SIZE)
		return false;

	/* Read encrypted data */
	res = f_read(file, s_work_buf, enc_len, &br);
	if (res != FR_OK || br != enc_len)
		return false;

	/* Pick the key for this record's file version. */
	if (version == WIFI_CRED_FILE_VERSION_V2)
	{
		if (!persistent_key_get(key))
		{
			memset(key, 0, sizeof(key));
			return false;
		}
	}
	else /* V1 — legacy */
	{
		m1_crypto_derive_key(key);
	}

	/* Decrypt */
	plain_len = m1_crypto_decrypt_with_key(s_work_buf, enc_len, key);
	memset(key, 0, sizeof(key));
	if (plain_len == 0)
		return false;

	/* Parse: SSID\0PASSWORD\0 */
	ssid_ptr = (const char *)s_work_buf;
	ssid_len = strlen(ssid_ptr);

	if (ssid_len == 0 || ssid_len >= WIFI_CRED_SSID_MAX_LEN)
		return false;

	if (ssid_len + 1 >= plain_len)
		return false; /* No room for password */

	pass_ptr = ssid_ptr + ssid_len + 1;

	strncpy(cred->ssid, ssid_ptr, WIFI_CRED_SSID_MAX_LEN - 1);
	cred->ssid[WIFI_CRED_SSID_MAX_LEN - 1] = '\0';

	strncpy(cred->password, pass_ptr, WIFI_CRED_PASS_MAX_LEN - 1);
	cred->password[WIFI_CRED_PASS_MAX_LEN - 1] = '\0';

	cred->valid = true;

	/* Clear work buffer */
	memset(s_work_buf, 0, WIFI_CRED_WORK_BUF_SIZE);

	return true;
} // static bool read_record(...)



/*============================================================================*/
/*
 * Write a single credential as an encrypted record to file
 */
/*============================================================================*/
static bool write_record(FIL *file, const wifi_credential_t *cred)
{
	uint32_t plain_len;
	uint32_t enc_len;
	uint8_t len_buf[4];
	UINT bw;
	FRESULT res;
	size_t ssid_len;
	size_t pass_len;

	if (cred == NULL || !cred->valid)
		return false;

	/* Build plaintext: SSID\0PASSWORD\0 */
	ssid_len = strlen(cred->ssid);
	pass_len = strlen(cred->password);
	plain_len = ssid_len + 1 + pass_len + 1; /* Both null terminators included */

	if (plain_len > WIFI_CRED_PLAIN_MAX_SIZE)
		return false;

	memset(s_work_buf, 0, WIFI_CRED_WORK_BUF_SIZE);
	memcpy(s_work_buf, cred->ssid, ssid_len);
	s_work_buf[ssid_len] = '\0';
	memcpy(&s_work_buf[ssid_len + 1], cred->password, pass_len);
	s_work_buf[ssid_len + 1 + pass_len] = '\0';

	/* Encrypt with the persistent OTP-stored key (Phase 5.10). If OTP
	 * cannot be read or programmed (e.g. previous firmware used the
	 * slot for a different magic), fall back to the legacy UID-derived
	 * key — this is also why write_file_header() emits v1 in that case. */
	uint8_t key[M1_CRYPTO_AES_KEY_SIZE];
	if (persistent_key_get(key))
	{
		enc_len = m1_crypto_encrypt_with_key(s_work_buf, plain_len,
		                                     WIFI_CRED_WORK_BUF_SIZE, key);
	}
	else
	{
		m1_crypto_derive_key(key);
		enc_len = m1_crypto_encrypt_with_key(s_work_buf, plain_len,
		                                     WIFI_CRED_WORK_BUF_SIZE, key);
	}
	memset(key, 0, sizeof(key));
	if (enc_len == 0)
		return false;

	/* Write encrypted length (4 bytes, little-endian) */
	len_buf[0] = (uint8_t)(enc_len & 0xFF);
	len_buf[1] = (uint8_t)((enc_len >> 8) & 0xFF);
	len_buf[2] = (uint8_t)((enc_len >> 16) & 0xFF);
	len_buf[3] = (uint8_t)((enc_len >> 24) & 0xFF);

	res = f_write(file, len_buf, 4, &bw);
	if (res != FR_OK || bw != 4)
		return false;

	/* Write encrypted data */
	res = f_write(file, s_work_buf, enc_len, &bw);
	if (res != FR_OK || bw != enc_len)
		return false;

	/* Clear work buffer */
	memset(s_work_buf, 0, WIFI_CRED_WORK_BUF_SIZE);

	return true;
} // static bool write_record(...)



/*============================================================================*/
/*
 * Write all credentials from the in-memory cache to file.
 * Rewrites the entire file.
 */
/*============================================================================*/
static bool write_all_credentials(void)
{
	FIL file;
	FRESULT res;
	uint8_t i;
	uint8_t valid_count = 0;

	if (!ensure_system_dir())
		return false;

	/* Count valid credentials */
	for (i = 0; i < s_cred_cache_count; i++)
	{
		if (s_cred_cache[i].valid)
			valid_count++;
	}

	res = f_open(&file, WIFI_CRED_FILE_PATH, FA_WRITE | FA_CREATE_ALWAYS);
	if (res != FR_OK)
		return false;

	/* Write header */
	if (!write_file_header(&file, valid_count))
	{
		f_close(&file);
		return false;
	}

	/* Write each valid credential */
	for (i = 0; i < s_cred_cache_count; i++)
	{
		if (s_cred_cache[i].valid)
		{
			if (!write_record(&file, &s_cred_cache[i]))
			{
				f_close(&file);
				return false;
			}
		}
	}

	f_close(&file);
	return true;
} // static bool write_all_credentials(void)



/*============================================================================*/
/*
 * Load all saved credentials from SD card.
 * Decrypts each record automatically.
 * Returns the number of valid credentials loaded.
 */
/*============================================================================*/
uint8_t wifi_cred_load_all(wifi_credential_t *creds, uint8_t max_count)
{
	FIL file;
	FRESULT res;
	uint8_t record_count = 0;
	uint8_t loaded = 0;
	uint8_t i;

	if (creds == NULL || max_count == 0)
		return 0;

	memset(creds, 0, sizeof(wifi_credential_t) * max_count);

	res = f_open(&file, WIFI_CRED_FILE_PATH, FA_READ);
	if (res != FR_OK)
		return 0;

	uint8_t file_version = WIFI_CRED_FILE_VERSION_V1;
	if (!read_file_header(&file, &record_count, &file_version))
	{
		f_close(&file);
		return 0;
	}

	for (i = 0; i < record_count && loaded < max_count; i++)
	{
		if (read_record(&file, &creds[loaded], file_version))
		{
			loaded++;
		}
		else
		{
			/* Skip corrupted records - try to continue */
			break; /* Can't reliably skip variable-length records */
		}
	}

	f_close(&file);

	/* Update the internal cache as well */
	s_cred_cache_count = loaded;
	if (loaded > 0)
	{
		memcpy(s_cred_cache, creds,
		       sizeof(wifi_credential_t) * ((loaded < WIFI_CRED_MAX_STORED) ? loaded : WIFI_CRED_MAX_STORED));
	}

	return loaded;
} // uint8_t wifi_cred_load_all(...)



/*============================================================================*/
/*
 * Save a new credential. If the SSID already exists, update the password.
 * Encrypts and writes to SD card.
 * Returns true on success.
 */
/*============================================================================*/
bool wifi_cred_save(const char *ssid, const char *password)
{
	uint8_t i;
	int existing_idx = -1;
	wifi_credential_t temp_creds[WIFI_CRED_MAX_STORED];

	if (ssid == NULL || password == NULL)
		return false;

	if (strlen(ssid) == 0 || strlen(ssid) >= WIFI_CRED_SSID_MAX_LEN)
		return false;

	if (strlen(password) >= WIFI_CRED_PASS_MAX_LEN)
		return false;

	/* Load current credentials into cache if not already loaded */
	if (s_cred_cache_count == 0)
	{
		s_cred_cache_count = wifi_cred_load_all(temp_creds, WIFI_CRED_MAX_STORED);
		if (s_cred_cache_count > 0)
			memcpy(s_cred_cache, temp_creds, sizeof(wifi_credential_t) * s_cred_cache_count);
	}

	/* Check if SSID already exists */
	for (i = 0; i < s_cred_cache_count; i++)
	{
		if (s_cred_cache[i].valid && strcmp(s_cred_cache[i].ssid, ssid) == 0)
		{
			existing_idx = i;
			break;
		}
	}

	if (existing_idx >= 0)
	{
		/* Update existing credential */
		strncpy(s_cred_cache[existing_idx].password, password, WIFI_CRED_PASS_MAX_LEN - 1);
		s_cred_cache[existing_idx].password[WIFI_CRED_PASS_MAX_LEN - 1] = '\0';
	}
	else
	{
		/* Add new credential */
		if (s_cred_cache_count >= WIFI_CRED_MAX_STORED)
			return false; /* Storage full */

		strncpy(s_cred_cache[s_cred_cache_count].ssid, ssid, WIFI_CRED_SSID_MAX_LEN - 1);
		s_cred_cache[s_cred_cache_count].ssid[WIFI_CRED_SSID_MAX_LEN - 1] = '\0';
		strncpy(s_cred_cache[s_cred_cache_count].password, password, WIFI_CRED_PASS_MAX_LEN - 1);
		s_cred_cache[s_cred_cache_count].password[WIFI_CRED_PASS_MAX_LEN - 1] = '\0';
		s_cred_cache[s_cred_cache_count].valid = true;
		s_cred_cache_count++;
	}

	/* Rewrite the entire file */
	return write_all_credentials();
} // bool wifi_cred_save(...)



/*============================================================================*/
/*
 * Delete a credential by SSID.
 * Rewrites the file without the deleted credential.
 * Returns true if the credential was found and deleted.
 */
/*============================================================================*/
bool wifi_cred_delete(const char *ssid)
{
	uint8_t i;
	bool found = false;
	wifi_credential_t temp_creds[WIFI_CRED_MAX_STORED];

	if (ssid == NULL || strlen(ssid) == 0)
		return false;

	/* Load current credentials into cache if not already loaded */
	if (s_cred_cache_count == 0)
	{
		s_cred_cache_count = wifi_cred_load_all(temp_creds, WIFI_CRED_MAX_STORED);
		if (s_cred_cache_count > 0)
			memcpy(s_cred_cache, temp_creds, sizeof(wifi_credential_t) * s_cred_cache_count);
	}

	/* Find and mark the credential as invalid */
	for (i = 0; i < s_cred_cache_count; i++)
	{
		if (s_cred_cache[i].valid && strcmp(s_cred_cache[i].ssid, ssid) == 0)
		{
			/* Shift remaining entries down */
			uint8_t j;
			for (j = i; j < s_cred_cache_count - 1; j++)
			{
				memcpy(&s_cred_cache[j], &s_cred_cache[j + 1], sizeof(wifi_credential_t));
			}

			/* Clear the last slot */
			memset(&s_cred_cache[s_cred_cache_count - 1], 0, sizeof(wifi_credential_t));
			s_cred_cache_count--;
			found = true;
			break;
		}
	}

	if (!found)
		return false;

	/* Rewrite the file without the deleted credential */
	return write_all_credentials();
} // bool wifi_cred_delete(...)



/*============================================================================*/
/*
 * Find a credential by SSID.
 * Returns true if found, with the credential data in *out.
 */
/*============================================================================*/
bool wifi_cred_find(const char *ssid, wifi_credential_t *out)
{
	wifi_credential_t temp_creds[WIFI_CRED_MAX_STORED];
	uint8_t count;
	uint8_t i;

	if (ssid == NULL || out == NULL)
		return false;

	memset(out, 0, sizeof(wifi_credential_t));

	/* Try the cache first */
	if (s_cred_cache_count > 0)
	{
		for (i = 0; i < s_cred_cache_count; i++)
		{
			if (s_cred_cache[i].valid && strcmp(s_cred_cache[i].ssid, ssid) == 0)
			{
				memcpy(out, &s_cred_cache[i], sizeof(wifi_credential_t));
				return true;
			}
		}
	}

	/* Cache miss or empty - load from file */
	count = wifi_cred_load_all(temp_creds, WIFI_CRED_MAX_STORED);

	for (i = 0; i < count; i++)
	{
		if (temp_creds[i].valid && strcmp(temp_creds[i].ssid, ssid) == 0)
		{
			memcpy(out, &temp_creds[i], sizeof(wifi_credential_t));

			/* Clear temporary buffer containing passwords */
			memset(temp_creds, 0, sizeof(temp_creds));
			return true;
		}
	}

	/* Clear temporary buffer */
	memset(temp_creds, 0, sizeof(temp_creds));
	return false;
} // bool wifi_cred_find(...)
