cd mbedtls
make compile
python3 gen_data.py
cd ../../lattice-attack/
for data in ../ecdsa-polynomial-nonce-recurrence-attack/mbedtls/data/*; do
    time python3 lattice_attack.py -f $data
done > ../ecdsa-polynomial-nonce-recurrence-attack/out.txt;