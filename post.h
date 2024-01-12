#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define CPU_PROVIDER_ID UINT32_MAX

typedef enum DeviceClass {
  CPU = 1,
  GPU = 2,
} DeviceClass;

typedef enum InitializeResult {
  InitializeOk = 0,
  InitializeOkNonceNotFound = 1,
  InitializeInvalidLabelsRange = 2,
  InitializeError = 3,
  InitializeInvalidArgument = 4,
  InitializeFailedToGetProviders = 5,
} InitializeResult;

/**
 * An enum representing the available verbosity levels of the logger.
 *
 * Typical usage includes: checking if a certain `Level` is enabled with
 * [`log_enabled!`](macro.log_enabled.html), specifying the `Level` of
 * [`log!`](macro.log.html), and comparing a `Level` directly to a
 * [`LevelFilter`](enum.LevelFilter.html).
 */
enum Level {
  /**
   * The "error" level.
   *
   * Designates very serious errors.
   */
  Error = 1,
  /**
   * The "warn" level.
   *
   * Designates hazardous situations.
   */
  Warn,
  /**
   * The "info" level.
   *
   * Designates useful information.
   */
  Info,
  /**
   * The "debug" level.
   *
   * Designates lower priority information.
   */
  Debug,
  /**
   * The "trace" level.
   *
   * Designates very low priority, often extremely verbose, information.
   */
  Trace,
};
typedef uintptr_t Level;

typedef enum VerifyResult {
  Ok,
  Invalid,
  InvalidArgument,
  FailedToCreateVerifier,
  Failed,
} VerifyResult;

typedef struct Initializer Initializer;

typedef struct Verifier Verifier;

typedef struct Provider {
  char name[64];
  uint32_t id;
  enum DeviceClass class_;
} Provider;

/**
 * Scrypt algorithm parameters.
 *
 * Refer to <https://www.rfc-editor.org/rfc/rfc7914#section-2>
 */
typedef struct ScryptParams {
  /**
   * N = 1 << (nfactor + 1)
   */
  uint8_t nfactor;
  /**
   * r = 1 << rfactor
   */
  uint8_t rfactor;
  /**
   * p = 1 << pfactor
   */
  uint8_t pfactor;
} ScryptParams;

/**
 * FFI-safe borrowed Rust &str
 */
typedef struct StringView {
  const char *ptr;
  uintptr_t len;
} StringView;

typedef struct ExternCRecord {
  Level level;
  struct StringView message;
  struct StringView module_path;
  struct StringView file;
  int64_t line;
} ExternCRecord;

typedef struct ArrayU8 {
  uint8_t *ptr;
  uintptr_t len;
  uintptr_t cap;
} ArrayU8;

typedef struct Proof {
  uint32_t nonce;
  struct ArrayU8 indices;
  uint64_t pow;
  struct ArrayU8 pow_creator;
} Proof;

typedef struct Config {
  /**
   * K1 specifies the difficulty for a label to be a candidate for a proof.
   */
  uint32_t k1;
  /**
   * K2 is the number of labels below the required difficulty required for a proof.
   */
  uint32_t k2;
  /**
   * K3 is the size of the subset of proof indices that is validated.
   */
  uint32_t k3;
  /**
   * Difficulty for the nonce proof of work. Lower values increase difficulty of finding
   * `pow` for [Proof][crate::prove::Proof].
   */
  uint8_t pow_difficulty[32];
  /**
   * Scrypt paramters for initilizing labels
   */
  struct ScryptParams scrypt;
} Config;

/**
 * RandomX Flags are used to configure the library.
 */
typedef uint32_t RandomXFlag;
/**
 * No flags set. Works on all platforms, but is the slowest.
 */
#define RandomXFlag_FLAG_DEFAULT (uint32_t)0
/**
 * Allocate memory in large pages.
 */
#define RandomXFlag_FLAG_LARGE_PAGES (uint32_t)1
/**
 * Use hardware accelerated AES.
 */
#define RandomXFlag_FLAG_HARD_AES (uint32_t)2
/**
 * Use the full dataset.
 */
#define RandomXFlag_FLAG_FULL_MEM (uint32_t)4
/**
 * Use JIT compilation support.
 */
#define RandomXFlag_FLAG_JIT (uint32_t)8
/**
 * When combined with FLAG_JIT, the JIT pages are never writable and executable at the
 * same time.
 */
#define RandomXFlag_FLAG_SECURE (uint32_t)16
/**
 * Optimize Argon2 for CPUs with the SSSE3 instruction set.
 */
#define RandomXFlag_FLAG_ARGON2_SSSE3 (uint32_t)32
/**
 * Optimize Argon2 for CPUs with the AVX2 instruction set.
 */
#define RandomXFlag_FLAG_ARGON2_AVX2 (uint32_t)64
/**
 * Optimize Argon2 for CPUs without the AVX2 or SSSE3 instruction sets.
 */
#define RandomXFlag_FLAG_ARGON2 (uint32_t)96

typedef struct ProofMetadata {
  uint8_t node_id[32];
  uint8_t commitment_atx_id[32];
  uint8_t challenge[32];
  uint32_t num_units;
  uint64_t labels_per_unit;
} ProofMetadata;

/**
 * Returns the number of providers available.
 */
uintptr_t get_providers_count(void);

/**
 * Returns all available providers.
 */
enum InitializeResult get_providers(struct Provider *out, uintptr_t out_len);

/**
 * Initializes labels for the given range.
 *
 * start and end are inclusive.
 */
enum InitializeResult initialize(struct Initializer *initializer,
                                 uint64_t start,
                                 uint64_t end,
                                 uint8_t *out_buffer,
                                 uint64_t *out_nonce);

struct Initializer *new_initializer(uint32_t provider_id,
                                    uintptr_t n,
                                    const uint8_t *commitment,
                                    const uint8_t *vrf_difficulty);

void free_initializer(struct Initializer *initializer);

enum VerifyResult verify_pos(const char *datadir,
                             const uint32_t *from_file,
                             const uint32_t *to_file,
                             double fraction,
                             struct ScryptParams scrypt);

/**
 * Set a logging callback function
 * The function is idempotent, calling it more then once will have no effect.
 * Returns 0 if the callback was set successfully, 1 otherwise.
 */
int32_t set_logging_callback(Level level, void (*callback)(const struct ExternCRecord*));

/**
 * Deallocate a proof obtained with generate_proof().
 * # Safety
 * `proof` must be a pointer to a Proof struct obtained with generate_proof().
 */
void free_proof(struct Proof *proof);

/**
 * Generates a proof of space for the given challenge using the provided parameters.
 * Returns a pointer to a Proof struct which should be freed with free_proof() after use.
 * If an error occurs, prints it on stderr and returns null.
 * # Safety
 * `challenge` must be a 32-byte array.
 * `miner_id` must be null or point to a 32-byte array.
 */
struct Proof *generate_proof(const char *datadir,
                             const unsigned char *challenge,
                             struct Config cfg,
                             uintptr_t nonces,
                             uintptr_t threads,
                             RandomXFlag pow_flags,
                             const unsigned char *miner_id);

/**
 * Get the recommended RandomX flags
 *
 * Does not include:
 * * FLAG_LARGE_PAGES
 * * FLAG_FULL_MEM
 * * FLAG_SECURE
 *
 * The above flags need to be set manually, if required.
 */
RandomXFlag recommended_pow_flags(void);

enum VerifyResult new_verifier(RandomXFlag flags, struct Verifier **out);

void free_verifier(struct Verifier *verifier);

/**
 * Verify a proof
 *
 * # Safety
 * `metadata` must be initialized and properly aligned.
 */
enum VerifyResult verify_proof(const struct Verifier *verifier,
                               struct Proof proof,
                               const struct ProofMetadata *metadata,
                               struct Config cfg);
