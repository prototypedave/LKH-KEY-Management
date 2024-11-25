# Comprehensive Key Management and Secure Communication Systems

## Overview
This repository contains three interconnected sub-projects designed to provide advanced key management and secure communication solutions for modern networks:

1. **LKH Key System:** A scalable key management system using the Logical Key Hierarchy (LKH) approach.
2. **DTLS:** Implementation of Datagram Transport Layer Security for encrypted and authenticated communication over unreliable transport protocols.
3. **Flat Key Network System:** A lightweight key management framework for networks requiring simple and direct key-sharing mechanisms.

These systems aim to enhance network security, scalability, and efficiency in various use cases such as IoT, enterprise communication, and distributed systems.

## Features
- **Secure Communication:** Ensures encryption, authentication, and integrity for sensitive data.
- **Scalability:** LKH supports hierarchical key structures for efficient group key management.
- **Flexibility:** Offers different systems to cater to diverse network security needs.
- **Lightweight Implementation:** Suitable for resource-constrained environments like IoT devices.

## System Architecture
The project consists of:
1. A Key Management Layer that handles the creation, distribution, and revocation of keys.
2. A Security Layer built on DTLS for communication-level encryption.
3. A Networking Layer supporting flat and hierarchical key structures.

Each sub-project operates independently but can integrate into a unified system for enhanced functionality.

## Setup

### Prerequisites
- **Operating System:** Linux or Windows (preferably with WSL for Linux-like experience).
- **Development Tools:** GCC/Clang (for Linux) or MinGW/MSYS2 (for Windows).
- **Libraries:** OpenSSL, OMNeT++, INET Framework.

### Installation
#### 1.Install OMNeT++
- Install OpenSSL on your system:
``` bash
    sudo apt install openssl libssl-dev
 ```
- Download the OMNeT++ source code from the [OMNeT++ Website](https://omnetpp.org/)
- Extract the package:
``` bash
    tar xvf omnetpp-<version>.tar.gz
```
- Add openssl to the configure.user file in omnetpp directory
```bash
    # OpenSSL Include and Library Directories
    OPENSSL_INCLUDE_DIRS = /usr/include/openssl
    OPENSSL_LIBRARY_DIRS = /usr/lib/x86_64-linux-gnu

    # Add OpenSSL to INCLUDE_DIRS
    INCLUDE_DIRS += $(OPENSSL_INCLUDE_DIRS)

    # Add OpenSSL to LIBRARY_DIRS
    LIBRARY_DIRS += $(OPENSSL_LIBRARY_DIRS)

    # Link OpenSSL libraries (SSL and Crypto)
    LIBRARIES += ssl crypto
```
- Now you can contiue with the remaining instructions of installing omnetpp as documented on there site.

#### Install Inet
Download Inet framework from [GitHub](https://github.com/inet-framework/inet)
Navigate into the inets application folder and clone this repo
``` bash
    git clone https://github.com/prototypedave/LKH-KEY-Management.git
```
Then build inet and other frameworks from the IDE.

## LKH Key System
The Logical Key Hierarchy (LKH) system organizes keys in a hierarchical tree structure to optimize group key management.

### Features
- Efficient group key updates.
- Reduces communication overhead during key revocation.
- Scalable for large groups.

**Project:** lkh

### Network
(lkh)[docs/images/lkh.png]

## DTLS
The Datagram Transport Layer Security (DTLS) implementation ensures secure communication over UDP.

### Features
- Provides encryption, authentication, and replay protection.
- Handles packet loss gracefully.
- Suitable for real-time communication (e.g., VoIP, streaming).

**Project:** dtls

### Network
(lkh)[docs/images/dtls.png]

## Flat Key Network System
The Flat Key Network System provides a straightforward mechanism for key distribution in flat, non-hierarchical networks.

### Features
- Simplified key management.
- Ideal for small-scale networks.
- Low computational overhead.

**Project:** flat

### Network
(lkh)[docs/images/flat.png]

## Usage
You can integrate these sub-projects into your larger system or run them independently. Use the provided test scripts for functional verification. Contact me on (Email)[popupgfj@gmail.com]

## Contributing
Contributions are welcomed!