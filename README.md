# LocalVPN - Securing Local Network Access on Android

## Overview

LocalVPN is an Android application designed to protect users' local networks by monitoring and controlling which applications can access devices on the local network. Unlike existing firewall solutions that block all internet access, LocalVPN specifically focuses on local network traffic, giving users granular control over which apps can communicate with IoT devices, routers, and other local network resources.

## Motivation

With the proliferation of IoT devices and smart home technology, local networks have become increasingly attractive targets for malicious actors. While iOS 14+ provides built-in prompts when apps attempt to access the local network, Android lacks comparable protection. This creates a security gap where:

- Malicious apps can scan and fingerprint local networks
- IoT devices with weak security can be compromised
- Sensitive data (MAC addresses, device models, geolocation) can be harvested
- Routers can be attacked through DNS rebinding and other techniques

LocalVPN addresses this gap by providing Android users with visibility and control over local network access.

## Features

- **Real-time Monitoring**: Continuously monitors outgoing network traffic targeting local network IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- **Instant Notifications**: Alerts users when any app attempts to access the local network for the first time
- **User Control**: Simple Allow/Block decisions for each app attempting local network access
- **Non-invasive**: Only intercepts local network traffic; internet access remains unaffected
- **No Root Required**: Uses Android's VPN Service API to function without requiring device root access

## How It Works

LocalVPN leverages Android's `VpnService` API to create a virtual network interface that intercepts packets destined for private IP address ranges. When an application attempts to access the local network:

1. The packet is captured by the VPN service
2. The application is identified by its package name
3. A notification is sent to the user with Allow/Block options
4. User's decision is stored and applied to future traffic from that app
5. Allowed traffic proceeds normally; blocked traffic is dropped


## Requirements

- Android 6.0 (API level 23) or higher
- VPN permission (requested at runtime)

## Installation

## Usage

1. Launch the LocalVPN app
2. Grant VPN permission when prompted
3. The VPN service starts automatically
4. When an app attempts to access your local network, you'll receive a notification
5. Tap **Allow** to permit access or **Block** to deny it
6. Your decision is remembered for future access attempts

**Note**: A key icon in the notification bar indicates the VPN is active.

## Testing

The application has been tested on:
- **Virtual Devices**: Pixel 2 API 30, Pixel 4 API 34
- **Physical Device**: Redmi Note 8T

### Example Test Case

Attempting to access a home router (192.168.x.x) through Chrome browser:
- **Without LocalVPN**: Direct access to router login page
- **With LocalVPN**: Notification appears; blocking prevents access while allowing normal internet browsing

## Research Findings

During testing, we discovered several apps accessing the local network unexpectedly:
- **G4 Connect**: Attempted to find the router's IP address immediately upon opening, even before user login

## Architecture

```
┌─────────────────┐
│   Android App   │
└────────┬────────┘
         │ Local Network Packet
         ▼
┌─────────────────┐
│  VpnService     │ ◄── Intercepts local traffic only
└────────┬────────┘
         │
         ├──► Allowed? → Forward packet
         └──► Blocked? → Drop packet
```

## Limitations

- Currently stores allowed/blocked apps in memory (linked lists)
- Settings reset when app is closed (database migration planned)
- Only monitors outgoing traffic from the device

## Future Work

### Planned Features
- **Persistent Storage**: Migrate from linked lists to database for settings persistence
- **Kotlin Migration**: Rewrite codebase from Java to Kotlin for improved safety and maintainability
- **Enhanced UI**: Dashboard showing network activity statistics
- **Threat Detection**: Identify and flag potentially malicious apps
- **User Research**: Conduct usability studies and identify common apps accessing local networks

### Potential Applications
- **Enterprise Security**: Help organizations comply with data access regulations
- **Threat Intelligence**: Identify malicious applications for removal
- **Privacy Protection**: Prevent unauthorized device fingerprinting and tracking

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Related Research

This project is based on research conducted as part of a diploma thesis at the University of Thessaly. Key findings include:

- Android's permission model lacks fine-grained control for network access compared to iOS
- JavaScript-based attacks (DNS rebinding, XSS, CSRF) can compromise local networks
- IoT devices often have weak security, making them attractive targets
- Mobile apps can use mDNS and SSDP/UPnP to bypass Android's permission restrictions

## Academic Citation

If you use this work in academic research, please cite:

```bibtex
@mastersthesis{gianni2024securing,
  title={Securing Local Network Access on Android},
  author={Gianni, Ioanna},
  year={2024},
  school={University of Thessaly},
  type={Diploma Thesis},
  department={Department of Electrical and Computer Engineering},
  supervisor={Stamoulis, Georgios}
}
```

## Acknowledgments

- Based on the [LocalVPN project](https://github.com/hexene/LocalVPN) by hexene et al.
- Developed under the supervision of Professor Georgios Stamoulis
- Committee members: Professor Ioannis Moondanos, Professor Mathy Vanhoef (KU Leuven)
- Special thanks to PhD students Jeroen Robben and Angelos Beitis for their guidance

## References

For detailed information about local network security threats and Android permissions, see:
- [Full Thesis Document](docs/Gianni_Ioanna_thesis.pdf)
- [Android VPN Service Documentation](https://developer.android.com/develop/connectivity/vpn)
- [iOS Local Network Privacy](https://support.apple.com/en-us/102229)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


**Disclaimer**: This application is a research prototype developed for educational purposes. While it provides meaningful security benefits, it should not be considered a complete security solution. Users should maintain updated software, strong passwords, and follow security best practices for IoT devices.

## Security Notice

⚠️ **Important**: This app requires VPN permission to function. It does NOT send your data to external servers. All traffic analysis happens locally on your device. The VPN service only intercepts and analyzes packets destined for local network IP ranges (RFC 1918 addresses).
