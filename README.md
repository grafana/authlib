# Authlib

## Overview
The `Authlib` library provides a modular and secure approach to handling authentication and authorization within the Grafana ecosystem. It's designed to be flexible and easily adaptable to different deployment scenarios.

### Key Features
- **Composability:** Deploy in various configurations: in-process, on-premises gRPC, or Cloud gRPC.
- **OAuth2-Inspired Security:** Leverages familiar JWT-based authentication and authorization for robust security.
- **Modular Design:** Built with three core packages:
  - **`types`:** The types package is a dependency free set of types and interfaces that most consumers should depend on.
  - **[`authn`](./authn):** Varius components to handle authentication and identity propagation.
  - **[`authz`](./authz):** Authz client to perform authorization.
    - Single-tenant RBAC client, typically used by plugins to query Grafana for user permissions and control their access.
    - **[unstable / under development]** Multi-tenant client, typically used by multi-tenant applications to enforce service and user access.

## Documentation
Please see the [docs directory](docs/) for documentation

### License
This project is licensed under the Apache-2.0 license - see the [LICENSE](LICENSE) file for details.
