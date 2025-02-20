from weak_generator import generate_weak_signatures 

if __name__ == "__main__":
    file = open("../signatures/mock.txt", "w")
    pk, _, signatures = generate_weak_signatures(1000)
    file.write(pk + "\n")
    file.write(" ".join(signatures))
    file.close()
    print("Done")
    