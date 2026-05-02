/* TP-warning: branch on secret. Should produce a WARNING (not ERROR) since
 * branch predictor / cache effects make this a real but lower-severity risk. */

int check_pin(unsigned secret_pin, unsigned entered) {
    if (secret_pin == entered) {  /* JE/JNE on secret */
        return 1;
    }
    return 0;
}
