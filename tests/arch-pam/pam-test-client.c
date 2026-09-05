/* P0 test harness: drive a real libpam stack that lists pam_oma_id.so.
 *
 * Usage: pam-test-client <service> <username>
 * Prints "auth:<code> acct:<code>" where codes are libpam error numbers.
 * The conv function never prompts: the module under test must decide
 * without asking for a password, and any prompt is a protocol failure.
 */
#include <security/pam_appl.h>
#include <stdio.h>

/* Linux-PAM has no pam_message_t typedef: the conv callback takes struct
 * pointers. We never prompt; any prompt is a protocol failure. */
static int conv(const struct pam_message **message, struct pam_response **response,
                void *appdata) {
    (void)message;
    (void)response;
    (void)appdata;
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: pam-test-client <service> <username>\n");
        return 2;
    }
    const char *service = argv[1];
    const char *user = argv[2];

    struct pam_conv conv = { conv, NULL };
    pam_handle_t *pamh = NULL;
    int start_rc = pam_start(service, user, &conv, &pamh);
    if (start_rc != PAM_SUCCESS) {
        printf("auth:%d acct:-1\n", start_rc);
        return start_rc;
    }

    int auth_rc = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
    int acct_rc = -1;
    if (auth_rc == PAM_SUCCESS) {
        acct_rc = pam_acct_mgmt(pamh, 0);
    }
    int end_rc = pam_end(pamh, start_rc);
    if (end_rc != PAM_SUCCESS) {
        fprintf(stderr, "pam_end: %d\n", end_rc);
    }

    printf("auth:%d acct:%d\n", auth_rc, acct_rc);
    return auth_rc;
}
