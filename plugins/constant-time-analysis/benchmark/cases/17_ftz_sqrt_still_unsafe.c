/* TP across profiles: CT_FTZ_DAZ does NOT make SQRTSS constant-time. */

#define CT_FTZ_DAZ 1

float __builtin_sqrtf(float);

float bad_norm(float secret_x) {
    return __builtin_sqrtf(secret_x);
}
