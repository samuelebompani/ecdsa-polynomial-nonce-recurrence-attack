if [ "$#" -ne 2 ]; then
    echo "Found $# argument(s) but 2 are required"
    echo "Usage: $0 <number_of_known_bits> <number_of_signs>"
    exit 1
fi
cd mbedtls
make compile
echo "Compiled"
time python3 gen_data.py $1 $2
echo "Signatures generated"
cd ..
for data in ./mbedtls/data/*; do
    python3 ../lattice-attack/lattice_attack.py -f $data &
done > out.txt;
wait
echo ""
echo "Total tentatives: ";
cat out.txt | grep -o "Lattice ECDSA Attack" | wc -l
echo "Total successes: ";
cat out.txt | grep -o "Key found \o/" | wc -l
echo "Total failures: ";
cat out.txt | grep -o "Sorry" | wc -l