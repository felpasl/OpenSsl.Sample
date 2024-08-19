# Create keys

Alterar a senha "password"

```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048 -aes256 -pass pass:password

openssl rsa -pubout -in private_key.pem -out public_key.pem
```