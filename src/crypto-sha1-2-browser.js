'use strict'

const nodeify = require('nodeify')

const webCrypto = getWebCrypto()
const nCrypto = self.nCrypto

function getWebCrypto () {
  if (self.crypto) {
    return self.crypto.subtle || self.crypto.webkitSubtle
  }

  if (self.msCrypto) {
    return self.msCrypto.subtle
  }
}

function webCryptoHash (type) {
  if (!webCrypto) {
    throw new Error('Please use a browser with webcrypto support, or import nCrypto to the global namespace')
  }

  return (data, callback) => {
    const res = webCrypto.digest({ name: type }, data)

    if (typeof res.then !== 'function') { // IE11
      res.onerror = () => {
        callback(`Error hashing data using ${type}`)
      }
      res.oncomplete = (e) => {
        callback(null, e.target.result)
      }
      return
    }

    nodeify(
      res.then((raw) => new Buffer(new Uint8Array(raw))),
      callback
    )
  }
}

function nCryptoHash (type) {
  if (!nCrypto) {
    console.log('nCrypto not found by js-multihashing; falling back on webcrypto');
    return webCryptoHash(type)
  }

  return (data, callback) => {
    const hash = new nCrypto.Hash(type.toLowerCase());
    nodeify(
      hash.update(data).digest(),
      callback
    )
  }
}

function sha1 (buf, callback) {
  nCryptoHash('SHA-1')(buf, callback)
}

function sha2256 (buf, callback) {
  nCryptoHash('SHA-256')(buf, callback)
}

function sha2512 (buf, callback) {
  nCryptoHash('SHA-512')(buf, callback)
}

module.exports = {
  sha1: sha1,
  sha2256: sha2256,
  sha2512: sha2512
}
