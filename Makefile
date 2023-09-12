all: auditor

auditor: FORCE
	go build -o auditor ./src/cmd

FORCE: ;

generate: auditor
	for i in `ls rules/SCA/*`; do ./auditor vql "$$i" ./output; done
