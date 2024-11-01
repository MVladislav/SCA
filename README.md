# SCA Tooling

```sh
  MVladislav
```

---

- [SCA Tooling](#sca-tooling)
  - [Test Script to run Wazuh-SCA-YAML files](#test-script-to-run-wazuh-sca-yaml-files)
  - [Download other SCA-YAML files](#download-other-sca-yaml-files)
  - [SCA :: in work :: CIS Ubuntu 24.04](#sca--in-work--cis-ubuntu-2404)
  - [License](#license)
  - [References](#references)

---

## Test Script to run Wazuh-SCA-YAML files

Dependencies install for `wazuh-regex` and `yq`+`jq`:

```sh
$wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-manager/wazuh-manager_4.9.1-1_amd64.deb
$mkdir wazuh-manager && dpkg-deb -R wazuh-manager_4.9.1-1_amd64.deb wazuh-manager
$cp ./wazuh-manager/var/ossec/bin/wazuh-regex .
$mkdir wazuh-lib && cp -r ./wazuh-manager/var/ossec/lib/* ./wazuh-lib
$rm wazuh-manager* -rf
$chmod u+x wazuh-regex

$apt install yq jq
```

Examples how to run the script:

```sh
# Run all sca rules with file './cis_ubuntu24-04.yml'
$bash ./sca.sh -pdc

# Get help info
$bash ./sca.sh -h

# Run sca rule by ID from file './cis_ubuntu24-04.yml'
$bash ./sca.sh -soc -pdc -i <ID>
```

## Download other SCA-YAML files

```sh
$wget -O ./cis_ubuntu22-04.yml \
https://raw.githubusercontent.com/wazuh/wazuh/refs/heads/master/ruleset/sca/ubuntu/cis_ubuntu22-04.yml
```

## SCA :: in work :: CIS Ubuntu 24.04

- [x] Section1 (66)
- [x] Section2 (43)
- [x] Section3 (18)
- [x] Section4 (29)
- [x] Section5 (71)
- [ ] Section6 (62)
- [ ] Section7 (23)

---

## License

MIT

## References

- <https://github.com/MVladislav/ansible-cis-ubuntu-2404>
- <https://gist.github.com/MVladislav/b186d7dc6f151301cdd7b3943993d47c>
- <https://github.com/wazuh/wazuh/blob/enhancement/23194-create-sca-policy-for-ubuntu-24-04-lts/ruleset/sca/ubuntu/cis_ubuntu24-04.yml>
- Wazuh Docs
  - <https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/creating-custom-policies.html>
  - <https://github.com/wazuh/wazuh/blob/enhancement/23194-create-sca-policy-for-ubuntu-24-04-lts/ruleset/sca/ubuntu/cis_ubuntu24-04.yml>
- Wazuh Issues
  - <https://github.com/wazuh/wazuh/issues/7623>
  - <https://github.com/wazuh/wazuh/issues/23194>
