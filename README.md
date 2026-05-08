<br />
<div align="center">
  <h3 align="center">blocktion</h3>
  <p align="center">
      A blockchain and dApp for auctions built in Rust.
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## About

This repository contains an implementation of a PoW blockchain acting as a public ledger for a decentralized auction application built as a project for Security of Systems and Data class from the Master's Degree of Computer Science at FCUP.
<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Features

- [x] DHT overlay based on Kademlia for decentralized network construction.
- [x] PoW Blockchain with Blake2b hashing, Ed25519 signatures and Merkle Trees for transaction validation.
- [ ] Client for auctions using the blockchain layer as a public ledger.
- [ ] Docker autonomous network behaviour simulation with clients and bootstrap, well-behaved and malicious nodes.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Blockchain Protocol 

This sections specifies the protocol used to construct the blockchain layer, inspired by Bitcoin's [protocol documentation](https://en.bitcoin.it/wiki/Protocol_documentation).

### Standards

#### Hashes 

Hashing is done using a single round of Blake2b.

```
Input: I am not in danger, Skyler. I am the danger.
Expected Output: 3a141d45dea6b8af5bab5f942d88f3c0d48edcda84fac341d821d13d65896e2a7d5a8ec921da654301e72db33631fd94963e064056172f4d970a77625aa7ed93
```

Blocks and transactions are always encoded in JSON before they are hashed.

#### Signatures

Transactions are signed using ECDSA over the ED25519 elliptic curve, using a fork of `curve25519_dalek` adapted to use Blake2b for hashing.

<p align="right">(<a href="#readme-top">back to top</a>)</p>
