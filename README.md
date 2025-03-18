# Digi Hash Utility

A simple utility for encrypting and decrypting data using AES encryption.

## Installation
bash
npm install digi-hash-utility

## Features

- Encrypt data with AES encryption
- Decrypt AES encrypted data
- Configurable via environment variables or config file
- Support for both Node.js and React applications

## Usage
javascript
const { hashData, decodeData } = require('digi-hash-utility');
// Encrypt data
const originalData = { message: "Hello, world!", sensitive: true };
const encrypted = hashData(originalData);
console.log('Encrypted:', encrypted);
// Output: Encrypted: 7b8f9a0e1d2c3b4a5d6e7f8g9h0i1j2k...
// Decrypt data
const decrypted = decodeData(encrypted);
console.log('Decrypted:', decrypted);
// Output: Decrypted: { message: "Hello, world!", sensitive: true }

## Configuration

The library is configured using environment variables.

### Environment Variables

- `HOOK_SECRET_KEY` or `REACT_APP_HASH_SECRET_KEY`: The secret key used for encryption/decryption (required)
- `ENABLE_HASH_DATA` or `REACT_APP_ENABLE_HASH_DATA`: Enable/disable encryption (default: 'false')
- `ENABLE_DECODE_DATA` or `REACT_APP_ENABLE_DECODE_DATA`: Enable/disable decryption (default: 'false')
- `HASH_WHITE_LIST` or `REACT_APP_HASH_WHITE_LIST`: List of addresses to bypass encryption
- `HASH_EXCLUDE_PATH` or `REACT_APP_HASH_EXCLUDE_PATH`: List of paths to exclude from encryption/decryption

## Security Considerations

- Keep your secret key secure and never commit it to version control
- For production applications, use environment variables
- Consider using a strong, randomly generated key for better security
- Use the whitelist feature to bypass encryption for trusted addresses

## API Reference

### serverHashData(data, senderAddress)

Encrypts the provided data on the server side using AES encryption.

- **Parameters**: 
  - `data`: Any JSON-serializable data
  - `senderAddress` (optional): The sender's address for whitelist checking
- **Returns**: 
  - If encryption is enabled: A hexadecimal string representing the encrypted data
  - If encryption is disabled: The original data unchanged

### serverDecodeData(data, senderAddress, path)

Decrypts the provided encrypted data on the server side.

- **Parameters**: 
  - `data`: A hexadecimal string representing encrypted data
  - `senderAddress` (optional): The sender's address for whitelist checking
  - `path` (optional): The request path
- **Returns**: 
  - If decryption is enabled: The original decrypted data
  - If decryption is disabled or sender is whitelisted: The input data unchanged

### clientHashData(data, path, method)

Encrypts the provided data on the client side using AES encryption.

- **Parameters**: 
  - `data`: Any JSON-serializable data
  - `path` (optional): The request path
  - `method` (optional): The HTTP method
- **Returns**: 
  - If encryption is enabled: A hexadecimal string representing the encrypted data
  - If encryption is disabled: The original data unchanged

### clientDecodeData(response)

Decrypts the provided encrypted data in client response objects.

- **Parameters**: 
  - `response`: The response object containing encrypted data
- **Returns**: 
  - If decryption is enabled: Response with decrypted data
  - If decryption is disabled: The input response unchanged

## License

MIT
