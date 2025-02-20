echo "Total tentatives: ";
cat out.txt | grep -o "Lattice ECDSA Attack" | wc -l
echo "Total successes: ";
cat out.txt | grep -o "Key found \o/" | wc -l
echo "Total failures: ";
cat out.txt | grep -o "Sorry" | wc -l