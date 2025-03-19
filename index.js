/**
 * Digi Hash Utility
 * A utility for encrypting and decrypting data using AES encryption.
 */
const CryptoJS = require('crypto-js');
const {Buffer} = require("buffer");

// Check if we're in a Node.js environment before requiring dotenv
const isNode = typeof process !== 'undefined' && 
               process.versions != null && 
               process.versions.node != null;

// Only load dotenv in Node environment
if (isNode) {
  require('dotenv').config();
}

/**
 * Gets environment variables safely in both Node.js and browser environments
 * @param {string} key - The environment variable key
 * @param {any} defaultValue - Default value if not found
 * @returns {string} The environment variable value or default
 */
const getEnvVar = (key, defaultValue) => {
  if (isNode && process.env[key]) {
    return process.env[key];
  }
  // For browsers using webpack or similar bundlers that define process.env
  if (typeof process !== 'undefined' && process.env && process.env[key]) {
    return process.env[key];
  }
  // For Create React App and similar that use REACT_APP_ prefix
  const reactKey = `REACT_APP_${key}`;
  if (typeof process !== 'undefined' && process.env && process.env[reactKey]) {
    return process.env[reactKey];
  }
  return defaultValue;
};

/**
 * Gets the secret key from environment variables or config file
 * @returns {string} The secret key
 */
const getSecretKey = () => {
  const key = getEnvVar('HOOK_SECRET_KEY', '') || 
              getEnvVar('REACT_APP_HASH_SECRET_KEY', '');
  
  if (!key) {
    throw new Error('HOOK_SECRET_KEY not found in environment variables');
  }
  
  return key;
};

/**
 * Gets the ENABLE_HASH_DATA setting from environment variables
 * This setting determines whether encryption is enabled
 * @returns {string} The ENABLE_HASH_DATA setting value
 */
const getEnableHashData = () => {
  return getEnvVar('ENABLE_HASH_DATA', 'false') || 
         getEnvVar('REACT_APP_ENABLE_HASH_DATA', 'false');
};

/**
 * Gets the ENABLE_DECODE_DATA setting from environment variables
 * This setting determines whether decryption is enabled
 * @returns {string} The ENABLE_DECODE_DATA setting value
 */
const getEnableDecodeData = () => {
  return getEnvVar('ENABLE_DECODE_DATA', 'false') || 
         getEnvVar('REACT_APP_ENABLE_DECODE_DATA', 'false');
};

/**
 * Gets the whitelist of addresses from environment variables
 * @returns {Array} The whitelist of addresses
 */
const getWhiteList = () => {
  const whitelist = getEnvVar('HASH_WHITE_LIST', '') || 
                    getEnvVar('REACT_APP_HASH_WHITE_LIST', '');
  
  return whitelist ? whitelist.split(',').map(item => item.trim()) : [];
};

/**
 * Gets the excluded paths from environment variables
 * @returns {Array} The excluded paths
 */
const getExcludePath = () => {
  const excludePaths = getEnvVar('HASH_EXCLUDE_PATH', '') || 
                       getEnvVar('REACT_APP_HASH_EXCLUDE_PATH', '');
  
  return excludePaths ? excludePaths.split(',').map(item => item.trim()) : [];
};

/**
 * Encrypts data on the server side using AES encryption if enabled
 * @param {any} data - The data to encrypt
 * @param {string} senderAddress - The sender's address for whitelist checking
 * @returns {string|any} - Encrypted hex string if enabled, or original data if disabled
 */
const serverHashData = (data, senderAddress= '') => {
  const ENABLE_HASH_DATA = getEnableHashData();
  if (ENABLE_HASH_DATA === 'true') {
    const SECRET_KEY = getSecretKey();
    let hashData = JSON.stringify(data);
    hashData = CryptoJS.AES.encrypt(hashData, SECRET_KEY).toString();
    hashData = Buffer.from(hashData).toString('hex');
    return hashData;
  }
  return data;
};

/**
 * Decrypts data on the server side if decryption is enabled
 * @param {string|any} data - The encrypted hex string to decrypt
 * @param {string} senderAddress - The sender's address for whitelist checking
 * @param {string} path - The request path
 * @returns {any} - Decrypted data if enabled, or original data if disabled
 */
const serverDecodeData = (data, senderAddress = '', path) => {
  const ENABLE_DECODE_DATA = getEnableDecodeData();
  if (ENABLE_DECODE_DATA === 'true') {
    const HASH_WHITE_LIST = getWhiteList();
    if (HASH_WHITE_LIST.includes(senderAddress)) {
      return data;
    }
    const SECRET_KEY = getSecretKey();
    return decodeData(data, SECRET_KEY);
  }
  return data;
};

/**
 * Encrypts data on the client side using AES encryption if enabled
 * @param {Object} config - The request configuration object
 * @param {boolean|string} enableHashData - Flag indicating if encryption is enabled
 * @param {string} secretKey - The secret key used for encryption
 * @returns {Object} - Modified config with encrypted data if enabled, or original config if disabled
 */
const clientHashData = (config, enableHashData, secretKey) => {
  if (enableHashData === true || enableHashData === 'true') {
    let newConfig = config;
    if (config.method === 'patch' || config.method === 'post') {
      const hash = hashData(config.data, secretKey);
      newConfig = {...config, data: {hash}};
    }
    if (config.method === 'delete') {
      const hash = hashData(config.params, secretKey);
      newConfig = { ...config, params: { hash } };
    }
    if (config.method === 'get') {
      const hash = hashData(config.params, secretKey);
      newConfig = { ...config, params: { hash } };
    }
    return newConfig;
  }
  return config;
};

/**
 * Decrypts data in client response objects if decryption is enabled
 * Handles various response formats and structures
 * @param {Object} response - The response object containing encrypted data
 * @param {boolean|string} enableDecodeData - Flag indicating if decryption is enabled
 * @param {string} secretKey - The secret key used for decryption
 * @returns {Object} - Response with decrypted data if enabled
 */
const clientDecodeData = (response, enableDecodeData, secretKey) => {
  if (enableDecodeData === 'true' || enableDecodeData === true) {
    if (response?.data?.total) {
      response.data.data = decodeData(response?.data?.data, secretKey);
      return response;
    }
    if (response?.data) {
      if (typeof response?.data === 'object') {
        if (response?.data?.data) {
          response.data.data = decodeData(response?.data?.data, secretKey);
          return response;
        }
        return response;
      }
      response.data = decodeData(response?.data, secretKey);
      return response;
    }
  }
  return response;
};

/**
 * Helper function to decrypt data
 * @param {string} data - The encrypted hex string to decrypt
 * @param {string} secretKey - The secret key used for decryption
 * @returns {any} - The decrypted data, parsed as JSON if possible
 * @throws {Error} - If decryption fails, logs error and returns original data
 */
const decodeData = (data, secretKey) => {
  try {
    let tmpData = Buffer.from(data, 'hex').toString();
    tmpData = CryptoJS.AES.decrypt(tmpData, secretKey).toString(CryptoJS.enc.Utf8);
    return tmpData === '' ? tmpData : JSON.parse(tmpData);
  } catch (error) {
    console.error('Error decoding data:', error);
    return data; // Return original data on error
  }
}

/**
 * Helper function to encrypt data
 * @param {any} data - The data to encrypt
 * @param {string} secretKey - The secret key used for encryption
 * @returns {string} - The encrypted hex string
 * @throws {Error} - If encryption fails, logs error and returns original data
 */
const hashData = (data, secretKey) => {
  try {
    let hashData = JSON.stringify(data);
    hashData = CryptoJS.AES.encrypt(hashData, secretKey).toString();
    hashData = Buffer.from(hashData).toString('hex');
    return hashData;
  } catch (error) {
    console.error('Error hashing data:', error);
    return data; // Return original data on error
  }
};

module.exports = {
  serverHashData,
  serverDecodeData,
  clientHashData,
  clientDecodeData,
};
