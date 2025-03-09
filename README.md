# MiniSafe MicroVM

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/minisafe/microvm/workflows/CI/badge.svg)](https://github.com/minisafe/microvm/actions)
[![Security Audit](https://github.com/minisafe/microvm/workflows/Security%20Audit/badge.svg)](https://github.com/minisafe/microvm/actions)

An enterprise-grade, security-hardened lightweight micro virtual machine system with advanced isolation and CI/CD integration.

## Features

### Security Hardening

- **W^X (Write XOR Execute) Protection**: Memory pages are never simultaneously writable and executable, preventing code injection attacks.
- **Data Guards**: Prevents access to sensitive data across VM boundaries with memory isolation.
- **Secure Permissions Model**: Fine-grained control over artifact capabilities.
- **Built-in Security Auditing**: Continuous monitoring for security violations.

### Network Isolation and Control

- **Full Network Stack Control**: Complete management of the VM's network stack.
- **Network Namespace Isolation**: Each VM runs in its own network namespace.
- **Advanced Firewall Capabilities**: Rule-based traffic filtering with inbound/outbound control.
- **Port Forwarding**: Expose specific VM services to the host.
- **Bandwidth Management**: Limit network utilization per VM.
- **Custom Routing**: Configure custom routes for complex networking scenarios.

### CI/CD Integration

- **GitHub Integration**: Build artifacts directly from GitHub repositories.
- **Automated Deployment**: Fully automate the build and deployment process.
- **Hot-Reloading**: Update running applications without stopping them.
- **Build Caching**: Speed up builds with intelligent caching.

### Performance & Scalability

- **Lightweight Design**: Minimal overhead compared to traditional VMs.
- **Resource Limits**: Set CPU, memory, and I/O limits per VM.
- **Fully Concurrent**: Parallel build, execution, and monitoring.
- **Process Metrics**: Real-time monitoring of resource utilization.

## Installation

### Prerequisites

- Linux kernel 4.19+ with namespace support
- Rust 1.70.0+
- `ip` and `iptables` command-line tools

### From Source

```bash
# Clone the repository
git clone https://github.com/minisafe/microvm.git
cd microvm

# Build the project
cargo build --release

# Install the binary
sudo cp target/release/microvm /usr/local/bin/
```

### Using Cargo

```bash
cargo install minisafe-microvm
```

## Usage

MicroVM provides a comprehensive CLI for managing virtual machines, building applications from GitHub, and controlling the network stack.

### Basic Commands

```bash
# Create a new MicroVM
microvm create --id my-vm

# Build an artifact from GitHub
microvm build --id my-vm --repo-url https://github.com/example/app --wait

# Execute an artifact
microvm execute --id my-vm --artifact-id artifact_1234567890 -- --port 8080

# List artifacts and processes
microvm list --id my-vm --all

# Clean up a MicroVM
microvm cleanup --id my-vm
```

### Network Management

```bash
# Add port forwarding
microvm network port-forward --id my-vm --host-port 8080 --container-port 80

# Add firewall rule
microvm network firewall --id my-vm --action allow --direction inbound \
    --protocol tcp --port-range 80-443

# Create a network bridge
microvm network bridge --id my-vm --bridge-name br0 --interface eth0

# Configure IP address
microvm network config-ip --id my-vm --interface eth0 --ip-cidr 192.168.1.10/24

# Add a static route
microvm network route --id my-vm --destination 10.0.0.0/24 \
    --gateway 192.168.1.1 --interface eth0
```

### Security Configuration

```bash
# Enable W^X protection
microvm security enable-wx --id my-vm --enable

# Configure artifact permissions
microvm security permissions --id my-vm --artifact-id artifact_1234567890 \
    --allow-network --allow-fs-write --allowed-paths /tmp,/var/log

# Run security audit
microvm security audit --id my-vm --full
```

### Hot-Reloading

```bash
# Hot-reload an artifact
microvm hot-reload --id my-vm --artifact-id artifact_1234567890
```

## Architecture

MicroVM is built using a modular architecture with several key components:

1. **Core VM Engine**: Manages VM lifecycle, security features, and resource allocation.
2. **Artifact Builder**: Handles building applications from GitHub repositories.
3. **Network Controller**: Manages the network stack with namespace isolation.
4. **Security Manager**: Enforces security policies and performs audits.
5. **CLI Interface**: Provides a user-friendly command-line interface.

## Security Considerations

When deploying MicroVM in production environments, consider the following:

- Run MicroVM with the minimum required privileges.
- Regularly update MicroVM to get the latest security patches.
- Use the built-in security audit feature to check for vulnerabilities.
- Apply the principle of least privilege when configuring artifact permissions.
- Implement additional host-level security measures for sensitive environments.

## CI/CD Integration Example

Here's an example GitHub Actions workflow that uses MicroVM:

```yaml
name: Deploy with MicroVM

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3
      
      - name: Install MicroVM
        run: |
          curl -L https://github.com/minisafe/microvm/releases/latest/download/microvm-linux-x86_64 -o microvm
          chmod +x microvm
          sudo mv microvm /usr/local/bin/
      
      - name: Deploy application
        run: |
          # Create MicroVM
          microvm create --id ci-deploy --memory 2048 --cpu 2
          
          # Build from GitHub
          microvm build --id ci-deploy --repo-url $GITHUB_REPOSITORY --wait
          
          # Add port forwarding
          microvm network port-forward --id ci-deploy --host-port 8080 --container-port 80
          
          # Execute application
          microvm execute --id ci-deploy --artifact-id $(microvm list --id ci-deploy --artifacts | tail -1 | awk '{print $1}')
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure that your code adheres to our coding standards and passes all tests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

- The Linux kernel namespace and cgroups features
- The Rust community for providing excellent libraries
- All contributors who have helped improve MicroVM 