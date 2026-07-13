---
layout: default
title: Python HD wallet derivation
description: Install wallet-hd-derivation-kit from PyPI for typed, offline multi-chain BIP32 and SLIP10 derivation.
permalink: /python/
---

# Python

```sh
python -m pip install wallet-hd-derivation-kit
```

```python
import os
from wallet_hd_derivation_kit import derive_address

result = derive_address({"mnemonic": os.environ["WALLET_MNEMONIC"]}, chain="tron")
print(result["address"])
```

Python 3.10+ is supported. Pin `1.0.*` for compatible fixes and verify your lockfile. [Runnable example](https://github.com/devdasx/wallet-hd-derivation-kit/tree/main/examples/python).
