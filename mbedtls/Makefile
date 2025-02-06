#!make

default: compile

all: compile run

compile: 
	gcc ecdsa.c -o ecdsa -lmbedcrypto

run: 
	./ecdsa

example:
	python ./weak_generator.py

test: example
	./newattack.py ../signatures/mock.txt

attack: all
	./newattack.py ../signatures/signatures.txt

complete:
	./complete-attack.py 10 4