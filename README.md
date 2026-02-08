# univocity

On-chain split view protection for [forestrie](https://github.com/forestrie/)
transparency logs.

## Overview

univocity provides Solidity contracts that verify transparency log checkpoints
can only be published on-chain if they are consistent with previously published
checkpoints. This prevents log operators from presenting different views of the
log to different parties.

The verification logic implements the consistency proof format described in
[draft-bryce-cose-receipts-mmr-profile](https://robinbryce.github.io/draft-bryce-cose-receipts-mmr-profile/draft-bryce-cose-receipts-mmr-profile.html).

## Reference Implementation

The MMR algorithms are ported from the reference Python implementation:
[merkle-mountain-range-proofs](https://github.com/robinbryce/merkle-mountain-range-proofs)

## Usage

```shell
forge build   # build
forge test    # test
forge fmt     # format
```

## License

MIT
