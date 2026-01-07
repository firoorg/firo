# I2P Support in Firo

This document describes the I2P (Invisible Internet Project) support in Firo, which allows nodes to operate as I2P hidden services for enhanced privacy and censorship resistance.

## Overview

I2P is an anonymous network layer that allows for peer-to-peer communication. Similar to Tor, it provides privacy by routing traffic through multiple hops, but I2P uses a different architecture:

- **Garlic Routing**: I2P bundles multiple messages together for efficiency
- **Decentralized**: Unlike Tor's directory authorities, I2P is fully decentralized
- **Supports both TCP and UDP**: More versatile for P2P applications
- **Designed for hidden services**: Optimized for peer-to-peer applications

## Requirements

To use I2P with Firo, you need:

1. **I2P Router**: Running [I2P](https://geti2p.net/) or [i2pd](https://i2pd.website/)
2. **SAM Bridge**: The SAM (Simple Anonymous Messaging) bridge must be enabled
3. **Firo compiled with default settings**: I2P support is included by default

## Configuration

### Setting up I2P Router

#### Using i2pd (recommended)

1. Install i2pd from https://i2pd.website/
2. Enable the SAM bridge in `i2pd.conf`:

```ini
[sam]
enabled = true
address = 127.0.0.1
port = 7656
```

3. Restart i2pd

#### Using Java I2P

1. Install I2P from https://geti2p.net/
2. Access the I2P Router Console (usually at http://127.0.0.1:7657)
3. Navigate to Configure → Clients
4. Enable "SAM application bridge"
5. Save and restart

### Firo Configuration

Add the following to your `firo.conf`:

```ini
# Enable I2P SAM proxy
i2psam=127.0.0.1:7656

# Accept incoming I2P connections (optional, default: 1)
i2pacceptincoming=1
```

Or use command-line arguments:

```bash
firod -i2psam=127.0.0.1:7656 -i2pacceptincoming=1
```

### Network Isolation

To use I2P exclusively (no clearnet connections):

```bash
firod -i2psam=127.0.0.1:7656 -onlynet=i2p
```

To use both I2P and Tor:

```bash
firod -i2psam=127.0.0.1:7656 -onion=127.0.0.1:9050
```

## Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i2psam=<ip:port>` | I2P SAM proxy address | none (disabled) |
| `-i2pacceptincoming` | Accept incoming I2P connections | 1 (enabled) |
| `-onlynet=i2p` | Only connect via I2P network | - |

## I2P Address Format

I2P uses base32 addresses with the `.b32.i2p` suffix:

```
abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.b32.i2p
```

These addresses are 52 characters of base32 encoded data, representing a 256-bit hash of the destination's public key.

## Connecting to I2P Peers

You can manually connect to I2P peers using:

```bash
firo-cli addnode "abcd...xyz.b32.i2p:8168" add
```

Or in `firo.conf`:

```ini
addnode=abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst.b32.i2p:8168
```

## Network Topology

When using I2P:

1. **Outbound connections**: Firo connects to I2P peers through the SAM proxy
2. **Inbound connections**: If enabled, the SAM bridge creates a destination for your node
3. **Address announcement**: Your I2P address is shared with other I2P peers

## Privacy Considerations

### Advantages of I2P over Tor for P2P

- **Better NAT traversal**: I2P handles incoming connections natively
- **Decentralized**: No central directory authorities
- **Packet-based**: Better suited for P2P protocols
- **Faster for persistent connections**: Tunnels are optimized for long-lived connections

### Potential Privacy Leaks

- **Timing analysis**: Transaction timing could potentially be correlated
- **Eclipse attacks**: Using only I2P makes the network more susceptible to Sybil attacks
- **Destination persistence**: Your I2P destination remains constant unless manually changed

### Recommendations

1. **Use multiple networks**: Consider using both I2P and clearnet for better anonymity set
2. **Run continuously**: Intermittent use can be more fingerprintable
3. **Keep software updated**: Both Firo and I2P router

## Troubleshooting

### Common Issues

**SAM bridge not responding:**
- Verify I2P router is running
- Check SAM is enabled on the correct port
- Ensure firewall allows localhost connections

**No I2P peers found:**
- I2P needs time to build tunnels (can take 2-5 minutes)
- Ensure you have seed nodes configured
- Check I2P router logs for errors

**Connection timeouts:**
- I2P is slower than clearnet; increase timeout values
- Check I2P router tunnel count and health

### Debug Logging

Enable debug logging for I2P-related issues:

```bash
firod -debug=net -debug=i2p
```

## Technical Details

### Internal Representation

I2P addresses are stored internally using a "GarliCat" prefix (similar to OnionCat for Tor):
- Prefix: `FD60:DB4D:DDB5::/48`
- Used for internal routing decisions and address grouping

### Address Limitations

Due to storage constraints in the legacy Bitcoin address format:
- Full I2P addresses (52 chars base32) are truncated internally
- The full address string should be preserved separately for connections
- This affects logging output but not functionality

## See Also

- [I2P Project](https://geti2p.net/)
- [i2pd](https://i2pd.website/)
- [SAM Protocol Specification](https://geti2p.net/en/docs/api/samv3)
- [Tor Support in Firo](tor.md)
- [Firo GitHub Issue #1641](https://github.com/firoorg/firo/issues/1641)
