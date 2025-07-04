# sv2python

The Python language bindings for the [Stratum V2 Reference implementation](https://github.com/stratum-mining/stratum).

## Build and install locally

```shell
# Install dependencies
pip3 install --requirement requirements.txt

# Generate the bindings
bash ./scripts/generate-linux.sh
## OR
bash ./scripts/generate-macos.sh

# Install the package
pip3 install -e .
```

## Install from PyPI

todo
