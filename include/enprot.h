#ifndef ENPROT_H
#define ENPROT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

/* Result codes */
#define ENPROT_OK          0
#define ENPROT_ERR_PARSE   1
#define ENPROT_ERR_CRYPTO  2
#define ENPROT_ERR_IO      3
#define ENPROT_ERR_INVALID 4

/* Result of an enprot operation */
typedef struct {
    int code;
    const char *error;
} enprot_result_t;

/* Process a file with the given JSON config.
 *
 * Config JSON:
 * {
 *   "operation": "encrypt|decrypt|store|fetch|verify",
 *   "file": "/path/to/file.txt",
 *   "words": {"SECRET": "password"},
 *   "cipher": "aes-256-siv",
 *   "casdir": ".cas"
 * }
 *
 * Returns enprot_result_t with code ENPROT_OK on success.
 * If error is non-NULL, free it with enprot_free_error().
 */
enprot_result_t enprot_process(const char *config_json);

/* Get the enprot version string (static, do not free). */
const char *enprot_version(void);

/* Free an error string from enprot_result_t.error. */
void enprot_free_error(char *ptr);

#ifdef __cplusplus
}
#endif

#endif /* ENPROT_H */
