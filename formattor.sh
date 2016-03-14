#!/bin/bash

if [ $# -ne 1 ]; then
	echo "Usage: $0 path_to_public_key.pem"
	exit 1
fi

all=$(openssl rsa -text -pubin -in ${1} -noout | tail -n+2 | tr -d " ")

mod=""
mod_passed=false
exp=""

for i in $all ; do
	if [ "$i" = "Modulus:" ]; then
		mod_passed=false
		continue
	elif [ "$i" = "Exponent:" ]; then
		mod_passed=true
		continue
	fi

	$mod_passed && exp="${exp}${i}" || mod="${mod}${i}"
done

echo mod=\"$(python -c "print(int(0x${mod//:/}))")\"
echo exp=\"$(python -c "print(int(0x${exp//:/}))")\"
