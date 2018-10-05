# One-time-password-generator
This program generates a one-time password (OTP) based on RFC6238. This is a similar concept to Google Authenticator.

Compilation instructions using GCC:
gcc -o totp totp.c -lcrypto -lm
