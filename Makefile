all: auditor

auditor: FORCE
	go build -o auditor ./src/cmd

FORCE: ;

generate: auditor
	for i in `ls rules/SCA/*`; do ./auditor vql "$$i" ./output; done


# The following assumes the wazuh directory is above ours
update_sca: auditor
	./auditor sca ../wazuh/ruleset/sca/windows/cis_win10_enterprise.yml ./rules/SCA/cis_win10_enterprise.yml
	./auditor sca ../wazuh/ruleset/sca/darwin/22/cis_apple_macOS_13.x.yml ./rules/SCA/cis_apple_macOS_13.x.yml
	./auditor sca ../wazuh/ruleset/sca/debian/cis_debian11.yml ./rules/SCA/audit_cis_debian11.yml
