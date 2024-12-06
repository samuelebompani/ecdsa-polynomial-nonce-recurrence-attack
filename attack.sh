cd mbedtls/
make all
for i in $(seq 1 1000);
do
    ./newattack.py
done