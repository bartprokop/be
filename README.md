# BE - Be Encrypted

Opinionated Java library to facilitate encryption of applicaion persistent data.

## What problem BE solves

Purpose of BE is to provide self contained, no dependencies library that can be easilly used to encrypt data (primarily Strings) in rest and in transit. Example use-cases are: sensitive database columns or sending sensitive data over Internet. This small library build on JWE compact serialization (and extends it) to provide maximum interoperability between systems.
