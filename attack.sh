cd mbedtls/
for i in $(seq 1 1000);
do
    make all
    ./newattack.py
done