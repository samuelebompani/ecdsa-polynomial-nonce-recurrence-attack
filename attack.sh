cd mbedtls/
for i in $(seq 1 100000);
do
    make all
    ./newattack.py ../signatures/signatures.txt
done
