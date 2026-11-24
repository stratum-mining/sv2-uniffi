/*
 * The C API on its own: a C program that links only libsv2_sri and runs
 * each group of sv2_sri.h the way a server and a miner would, with the
 * error paths a C caller relies on.  Nothing else is linked, so the library
 * can be checked wherever it is built:
 *
 *   ./test.sh          (builds the library, runs cargo test and this)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sv2_sri.h>

static int failures;

#define CHECK(cond)                                                                         \
	do {                                                                                    \
		if (!(cond)) {                                                                      \
			fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #cond);        \
			failures++;                                                                     \
		}                                                                                   \
	} while (0)

#define CHECK_EQ(a, b)                                                                      \
	do {                                                                                    \
		long long a_ = (long long)(a), b_ = (long long)(b);                                 \
		if (a_ != b_) {                                                                     \
			fprintf(stderr, "%s:%d: %s is %lld, expected %lld\n", __FILE__, __LINE__, #a, a_, b_); \
			failures++;                                                                     \
		}                                                                                   \
	} while (0)

static Sv2SriBytes bytes(const void *p, size_t len) {
	Sv2SriBytes b;
	b.data = (const uint8_t *)p;
	b.len = (uint32_t)len;
	return b;
}

static int bytes_eq(Sv2SriBytes b, const char *s) {
	return b.len == strlen(s) && (b.len == 0 || memcmp(b.data, s, b.len) == 0);
}

static uint8_t authority_sk[32], authority_pk[32];

static void test_keys(void) {
	uint8_t pk[32], other_sk[32], other_pk[32];
	char text[SV2_SRI_AUTHORITY_BASE58_MAX];
	int n;

	CHECK_EQ(sv2_sri_authority_keypair_generate(authority_sk, authority_pk), SV2_SRI_OK);
	CHECK_EQ(sv2_sri_authority_pubkey(authority_sk, pk), SV2_SRI_OK);
	CHECK(memcmp(pk, authority_pk, 32) == 0);
	CHECK_EQ(sv2_sri_authority_keypair_generate(other_sk, other_pk), SV2_SRI_OK);
	CHECK(memcmp(other_pk, authority_pk, 32) != 0);

	n = sv2_sri_authority_pubkey_to_base58(authority_pk, text, sizeof(text));
	CHECK(n > 0 && (size_t)n == strlen(text));
	memset(pk, 0, sizeof(pk));
	CHECK_EQ(sv2_sri_authority_pubkey_from_base58(text, pk), SV2_SRI_OK);
	CHECK(memcmp(pk, authority_pk, 32) == 0);
	CHECK_EQ(sv2_sri_authority_pubkey_to_base58(authority_pk, text, 8), SV2_SRI_ERR_OVERFLOW);
	CHECK_EQ(sv2_sri_authority_pubkey_from_base58("9notbase58!", pk), SV2_SRI_ERR_INVALID);
	CHECK_EQ(sv2_sri_authority_pubkey_from_base58(NULL, pk), SV2_SRI_ERR_INVALID);
	CHECK_EQ(sv2_sri_authority_pubkey(NULL, pk), SV2_SRI_ERR_INVALID);
}

// A responder and an initiator through the three acts.
static int handshake(struct Sv2SriNoise **server, struct Sv2SriNoise **miner, const uint8_t *pinned) {
	uint8_t act1[SV2_SRI_ACT1_SIZE], act2[SV2_SRI_ACT2_SIZE];
	uint32_t now = (uint32_t)time(NULL);
	int r;

	*server = sv2_sri_noise_responder_new(authority_pk, authority_sk, 3600);
	*miner = sv2_sri_noise_initiator_new(pinned);
	if (!*server || !*miner) return SV2_SRI_ERR_INVALID;
	if ((r = sv2_sri_noise_initiator_step0(*miner, act1)) != SV2_SRI_OK) return r;
	if ((r = sv2_sri_noise_responder_step1(*server, act1, now, act2)) != SV2_SRI_OK) return r;
	return sv2_sri_noise_initiator_step2(*miner, act2, now);
}

static void test_handshake(void) {
	struct Sv2SriNoise *server, *miner;
	uint8_t other_sk[32], other_pk[32];

	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_SRI_OK);
	CHECK(sv2_sri_noise_is_transport(server));
	CHECK(sv2_sri_noise_is_transport(miner));
	CHECK(sv2_sri_noise_is_authenticated(miner));
	sv2_sri_noise_free(server);
	sv2_sri_noise_free(miner);

	// no pinned key: any responder, not authenticated
	CHECK_EQ(handshake(&server, &miner, NULL), SV2_SRI_OK);
	CHECK(sv2_sri_noise_is_transport(miner));
	CHECK(!sv2_sri_noise_is_authenticated(miner));
	sv2_sri_noise_free(server);
	sv2_sri_noise_free(miner);

	// pinned to another authority: the certificate is refused
	CHECK_EQ(sv2_sri_authority_keypair_generate(other_sk, other_pk), SV2_SRI_OK);
	CHECK_EQ(handshake(&server, &miner, other_pk), SV2_SRI_ERR_CERT);
	CHECK(!sv2_sri_noise_is_transport(miner));
	sv2_sri_noise_free(server);
	sv2_sri_noise_free(miner);

	// a key pair that does not match, and a zero validity, make no responder
	CHECK(sv2_sri_noise_responder_new(other_pk, authority_sk, 3600) == NULL);
	CHECK(sv2_sri_noise_responder_new(authority_pk, authority_sk, 0) == NULL);
	CHECK(sv2_sri_noise_responder_new(NULL, authority_sk, 3600) == NULL);
	sv2_sri_noise_free(NULL);
	CHECK(!sv2_sri_noise_is_transport(NULL));
}

// Encrypt `frame` on `from` and hand the wire bytes to `to` in pieces of
// `step` bytes; returns the plaintext frame length or a negative code.
static int send_frame(struct Sv2SriNoise *from, struct Sv2SriNoise *to, const uint8_t *frame, uint32_t len,
                      uint32_t step, uint8_t *out, uint32_t out_cap, int tamper) {
	uint32_t wire_cap = sv2_sri_noise_encrypted_frame_size(len), off = 0;
	uint8_t *wire = malloc(wire_cap);
	int n, r = SV2_SRI_ERR_INVALID;

	if (!wire) return SV2_SRI_ERR_OVERFLOW;
	n = sv2_sri_noise_encrypt_frame(from, frame, len, wire, wire_cap);
	if (n < 0) {
		free(wire);
		return n;
	}
	if (tamper) wire[n - 1] ^= 1;
	while (off < (uint32_t)n) {
		uint32_t piece = (uint32_t)n - off < step ? (uint32_t)n - off : step, out_len = 0, consumed = 0;
		r = sv2_sri_noise_read_frame(to, wire + off, piece, out, out_cap, &out_len, &consumed);
		if (r < 0) break;
		off += consumed;
		if (r == SV2_SRI_OK) {
			r = (int)out_len;
			break;
		}
		if (consumed == 0) {
			r = SV2_SRI_ERR_STATE;
			break;
		}
	}
	free(wire);
	return r;
}

static void test_transport_and_messages(void) {
	struct Sv2SriNoise *server, *miner;
	uint8_t frame[4096], got[4096];
	Sv2SriMessage m, back;
	Sv2SriFrameHeader h;
	int n, len;

	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_SRI_OK);

	// SetupConnection, miner to server, fed a byte at a time
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_SRI_MSG_SETUP_CONNECTION;
	m.u.setup_connection.protocol = 0;
	m.u.setup_connection.min_version = 2;
	m.u.setup_connection.max_version = 2;
	m.u.setup_connection.flags = 1;
	m.u.setup_connection.endpoint_host = bytes("pool.example.org", 16);
	m.u.setup_connection.endpoint_port = 3336;
	m.u.setup_connection.vendor = bytes("capi_test", 9);
	m.u.setup_connection.hardware_version = bytes("", 0);
	m.u.setup_connection.firmware = bytes("1.0", 3);
	m.u.setup_connection.device_id = bytes("", 0);
	len = sv2_sri_message_encode(&m, frame, sizeof(frame));
	CHECK(len > SV2_SRI_FRAME_HEADER_SIZE);
	CHECK_EQ(sv2_sri_message_encode(&m, frame, 10), SV2_SRI_ERR_OVERFLOW);
	n = send_frame(miner, server, frame, (uint32_t)len, 1, got, sizeof(got), 0);
	CHECK_EQ(n, len);
	CHECK(n == len && memcmp(got, frame, (size_t)len) == 0);
	CHECK_EQ(sv2_sri_frame_header_decode(got, (uint32_t)n, &h), SV2_SRI_OK);
	CHECK_EQ(h.msg_type, SV2_SRI_MSG_SETUP_CONNECTION);
	CHECK_EQ(h.msg_length, (uint32_t)len - SV2_SRI_FRAME_HEADER_SIZE);
	CHECK_EQ(sv2_sri_message_decode(h.extension_type, h.msg_type, got + SV2_SRI_FRAME_HEADER_SIZE, h.msg_length, &back),
	         SV2_SRI_OK);
	CHECK_EQ(back.msg_type, SV2_SRI_MSG_SETUP_CONNECTION);
	CHECK_EQ(back.u.setup_connection.endpoint_port, 3336);
	CHECK(bytes_eq(back.u.setup_connection.vendor, "capi_test"));
	CHECK(bytes_eq(back.u.setup_connection.endpoint_host, "pool.example.org"));
	// a byte short is truncated, a byte over is garbage
	CHECK(sv2_sri_message_decode(h.extension_type, h.msg_type, got + SV2_SRI_FRAME_HEADER_SIZE, h.msg_length - 1, &back) < 0);
	got[n] = 0x55;
	CHECK_EQ(sv2_sri_message_decode(h.extension_type, h.msg_type, got + SV2_SRI_FRAME_HEADER_SIZE, h.msg_length + 1, &back),
	         SV2_SRI_ERR_TRAILING);
	// a type this API has no record for is reported, not refused as broken
	CHECK_EQ(sv2_sri_message_decode(0, 0x7f, got + SV2_SRI_FRAME_HEADER_SIZE, h.msg_length, &back), SV2_SRI_ERR_UNSUPPORTED);

	// SetTarget, server to miner, in one piece; the channel_msg bit is the crate's
	memset(&m, 0, sizeof(m));
	m.msg_type = SV2_SRI_MSG_SET_TARGET;
	m.u.set_target.channel_id = 7;
	memset(m.u.set_target.maximum_target, 0xff, 32);
	m.u.set_target.maximum_target[31] = 0x00;
	len = sv2_sri_message_encode(&m, frame, sizeof(frame));
	CHECK(len > 0);
	CHECK(sv2_sri_msg_has_channel_bit(SV2_SRI_MSG_SET_TARGET));
	n = send_frame(server, miner, frame, (uint32_t)len, 4096, got, sizeof(got), 0);
	CHECK_EQ(n, len);
	CHECK_EQ(sv2_sri_frame_header_decode(got, (uint32_t)n, &h), SV2_SRI_OK);
	CHECK(h.extension_type & 0x8000);
	CHECK_EQ(sv2_sri_message_decode(h.extension_type, h.msg_type, got + SV2_SRI_FRAME_HEADER_SIZE, h.msg_length, &back),
	         SV2_SRI_OK);
	CHECK_EQ(back.u.set_target.channel_id, 7);
	CHECK_EQ(back.u.set_target.maximum_target[31], 0);

	// a frame larger than the reader allows fails at its header
	CHECK_EQ(send_frame(server, miner, frame, (uint32_t)len, 4096, got, 8, 0), SV2_SRI_ERR_OVERFLOW);
	sv2_sri_noise_free(server);
	sv2_sri_noise_free(miner);

	// a flipped bit on the wire fails the tag and ends the session
	CHECK_EQ(handshake(&server, &miner, authority_pk), SV2_SRI_OK);
	CHECK_EQ(send_frame(server, miner, frame, (uint32_t)len, 4096, got, sizeof(got), 1), SV2_SRI_ERR_CRYPTO);
	sv2_sri_noise_free(server);
	sv2_sri_noise_free(miner);
}

// A coinbase around a 12 byte extranonce slot in its scriptSig, split at
// the slot (the same one as the crate's own channel tests).
static const uint8_t cb_prefix[] = {
	1, 0, 0, 0, 1,                                                                         // version, one input
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // prevout hash
	0xff, 0xff, 0xff, 0xff,                                                                // prevout index
	16, 3, 0x10, 0x20, 0x30,                                                               // scriptSig: height push, then the slot
};
static const uint8_t cb_suffix[] = {
	0xff, 0xff, 0xff, 0xff,          // sequence
	1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x51, // one output
	0, 0, 0, 0,                      // lock time
};

static void test_channels(void) {
	static const uint8_t local[] = {0xaa, 0xbb};
	uint8_t easy[32], prefix[32], target[32], hash[32], zero[32] = {0};
	uint8_t extranonce[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	struct Sv2SriExtranonceAllocator *a;
	struct Sv2SriExtendedChannel *ch;
	Sv2SriChannelOpen o;
	Sv2SriPrebuiltJob job;
	Sv2SriSubmitSharesExtended share;
	Sv2SriBytes code;
	uint32_t job_id = 0;
	int32_t status = 99;

	memset(easy, 0xff, sizeof(easy));
	a = sv2_sri_extranonce_allocator_new(local, sizeof(local), 12, 1024);
	CHECK(a != NULL);
	if (!a) return;
	CHECK_EQ(sv2_sri_extranonce_allocator_rollable_size(a), 8);
	CHECK(sv2_sri_extranonce_allocator_new(local, sizeof(local), 12, 0) == NULL);

	memset(&o, 0, sizeof(o));
	o.channel_id = 7;
	o.user_identity = bytes("worker", 6);
	o.nominal_hash_rate = 1.0e6f;
	o.max_target = easy;
	o.min_extranonce_size = 8;
	o.share_batch_size = 1;
	o.expected_shares_per_minute = 8.0f;
	o.max_past_jobs = 4;
	ch = sv2_sri_extended_channel_new(a, &o, &status);
	CHECK(ch != NULL);
	CHECK_EQ(status, SV2_SRI_OK);
	if (!ch) {
		sv2_sri_extranonce_allocator_free(a);
		return;
	}
	CHECK_EQ(sv2_sri_extended_channel_extranonce_prefix(ch, prefix, sizeof(prefix)), 4);
	CHECK(memcmp(prefix, local, sizeof(local)) == 0);
	CHECK_EQ(sv2_sri_extended_channel_extranonce_prefix(ch, prefix, 2), SV2_SRI_ERR_OVERFLOW);
	CHECK_EQ(sv2_sri_extended_channel_set_target(ch, easy), SV2_SRI_OK);
	CHECK_EQ(sv2_sri_extended_channel_set_target(ch, zero), SV2_SRI_ERR_CH_TARGET);

	// a future job, activated by SetNewPrevHash
	memset(&job, 0, sizeof(job));
	job.version = 0x20000000;
	job.coinbase_tx_prefix = bytes(cb_prefix, sizeof(cb_prefix));
	job.coinbase_tx_suffix = bytes(cb_suffix, sizeof(cb_suffix));
	job.merkle_path = bytes(NULL, 0);
	CHECK_EQ(sv2_sri_extended_channel_prebuilt_job(ch, &job, &job_id), SV2_SRI_OK);
	CHECK(job_id != 0);
	CHECK_EQ(sv2_sri_extended_channel_job_target(ch, job_id, target), SV2_SRI_ERR_CH_JOB_ID);
	CHECK_EQ(sv2_sri_extended_channel_activate_job(ch, job_id + 1, zero, 0x1d00ffff, 1700000000), SV2_SRI_ERR_CH_JOB_ID);
	CHECK_EQ(sv2_sri_extended_channel_activate_job(ch, job_id, zero, 0x1d00ffff, 1700000000), SV2_SRI_OK);
	CHECK_EQ(sv2_sri_extended_channel_job_target(ch, job_id, target), SV2_SRI_OK);
	CHECK(memcmp(target, easy, 32) == 0);

	// the all-ones target takes any hash, once
	memset(&share, 0, sizeof(share));
	share.channel_id = 7;
	share.sequence_number = 1;
	share.job_id = job_id;
	share.nonce = 42;
	share.ntime = 1700000001;
	share.version = 0x20000000;
	share.extranonce = bytes(extranonce, sizeof(extranonce));
	CHECK_EQ(sv2_sri_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_SRI_SHARE_VALID);
	CHECK(memcmp(hash, zero, 32) != 0);
	status = sv2_sri_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL);
	CHECK_EQ(status, SV2_SRI_ERR_SHARE_DUPLICATE);
	code = sv2_sri_channel_error_code(status);
	CHECK(bytes_eq(code, "duplicate-share"));
	share.job_id = job_id + 1;
	CHECK_EQ(sv2_sri_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_SRI_ERR_SHARE_JOB_ID);
	share.job_id = job_id;
	share.nonce = 43;
	share.extranonce = bytes(extranonce, 4);
	CHECK_EQ(sv2_sri_extended_channel_validate_share(ch, &share, hash, NULL, 0, NULL), SV2_SRI_ERR_SHARE_EXTRANONCE_SIZE);
	CHECK_EQ(sv2_sri_channel_error_code(SV2_SRI_ERR_INTERNAL).len, 0);

	sv2_sri_extended_channel_free(ch);
	sv2_sri_extended_channel_free(NULL);
	sv2_sri_extranonce_allocator_free(a);
	sv2_sri_extranonce_allocator_free(NULL);
}

static void test_util(void) {
	uint8_t a[32] = {0}, b[32] = {0}, digest[32];
	// SHA-256("abc")
	static const uint8_t abc[32] = {
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	};

	sv2_sri_random(a, sizeof(a));
	sv2_sri_random(b, sizeof(b));
	CHECK(memcmp(a, b, sizeof(a)) != 0);
	sv2_sri_sha256((const uint8_t *)"abc", 3, digest);
	CHECK(memcmp(digest, abc, 32) == 0);
	CHECK_EQ(sv2_sri_noise_encrypted_frame_size(SV2_SRI_FRAME_HEADER_SIZE - 1), 0);
	CHECK_EQ(sv2_sri_noise_encrypted_frame_size(SV2_SRI_FRAME_HEADER_SIZE + 10),
	         SV2_SRI_ENCRYPTED_HEADER_SIZE + 10 + SV2_SRI_AEAD_MAC_SIZE);
}

int main(void) {
	test_keys();
	test_handshake();
	test_transport_and_messages();
	test_channels();
	test_util();
	if (failures) {
		fprintf(stderr, "capi_test: %d check(s) failed\n", failures);
		return 1;
	}
	printf("capi_test: all checks passed\n");
	return 0;
}
