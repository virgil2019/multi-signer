# Tools for signing message with diverse methods

## Usage

Use this repo as a library by adding the following code

```
import {SignerType, createSigner, Signer} from '/multi-signer/src';
```

Create a signer

```
const signer: Signer = createSigner(SignerType.<Type>, param);
```

The format of `param`

- `sk`
```
{
    sk: "0x1234567812345678123456781234567812345678123456781234567812345678"
}
```

- `kms`
```
{
    region: "us-east-1",
    keyId: "arn:aws:kms:us-east-1:171678255258:key/fa1facfe-6325-4872-9e38-2edd96d1458f"
}
```