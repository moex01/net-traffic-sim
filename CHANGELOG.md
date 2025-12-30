# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- RADIUS packet accumulation when serializer is None
  - Ensure RADIUS packets are properly accumulated before returning
  - Prevents packet loss in non-serializer mode

### Changed
- Updated all documentation dates from 2024 to 2025
- Corrected test count to 186 (verified via pytest collection)
- Verified protocol count accuracy (34 protocols)

## [0.1.0] - 2025-12-29

### Added
- **NTP Protocol**: Network Time Protocol (NTPv4) simulation
  - RFC 5905 compliant time synchronization
  - NTP query/response flows with realistic timing
  - Pool server simulation (pool.ntp.org style)
  - Stratum hierarchy support (1-16)
  - Polling interval mechanisms
  - 14 comprehensive test cases

- **RADIUS Protocol**: Remote Authentication Dial-In User Service
  - Enterprise authentication simulation
  - Access-Request/Accept/Reject/Challenge message flows
  - Authenticator validation (MD5-based)
  - Attribute handling (User-Name, User-Password, NAS-IP-Address, etc.)
  - Realistic accounting flows
  - 24 comprehensive test cases

- **Type Hints**: Comprehensive type annotations across protocol helpers
  - Python 3.10+ type syntax
  - Improved IDE support and code documentation

### Fixed
- Removed duplicate utility functions from protocol implementations
  - Consolidated helper functions in sharepoint.py
  - Eliminated code duplication across scanner/attacker modules

### Changed
- **Test Suite**: Expanded from 148 to 186 total tests
  - RADIUS: 24 new tests
  - NTP: 14 new tests
  - Improved test coverage and reliability

- **Documentation**: Updated protocol count to 34 supported protocols

### Maintenance
- Added `cov_annotate/` to .gitignore to prevent coverage artifacts in version control
- Improved commit message standards and git history cleanliness

## [Prior to 0.1.0]

Initial development phase with support for 33 network protocols including:
- Application Layer: HTTP, HTTPS, DNS, DHCP, FTP, SSH, SMTP, POP3, IMAP, etc.
- Network/Transport: TCP, UDP, ICMP, ARP
- Enterprise: SMB, LDAP, Kerberos, RDP
- Monitoring: SNMP, Syslog, NetFlow
- And more...

---

## Legend

- **Added**: New features or capabilities
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features or capabilities
- **Fixed**: Bug fixes
- **Security**: Security-related changes
- **Maintenance**: Chores, dependency updates, tooling
