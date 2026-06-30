This project currently expects the following local dependencies:

- `third_party/chipwhisperer`
- `third_party/pqm4`

Recommended setup:

```bash
mkdir -p third_party

git clone https://github.com/newaetech/chipwhisperer.git third_party/chipwhisperer

git clone https://github.com/mupq/pqm4.git third_party/pqm4
cd third_party/pqm4
git fetch --all --tags
git checkout -B hpc-round3 Round3
git submodule update --init --recursive
```