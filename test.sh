cd mbedtls/
for i in $(seq 1 100);
do
    make test
done