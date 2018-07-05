const fs = require("fs")
const externalIP = require("ext-ip")()
var cachedExternalIP

module.exports = {
  get: function getExternalIP(callback) {
    if (callback === undefined) {
      throw new Error("Expecting a callback.")
    }

    if (cachedExternalIP) {
      callback(null, cachedExternalIP)
      return
    }

    // Load from config/network.json if present.
    if (fs.existsSync("../config/network.json")) {
      var networkConfig = require("../config/network.json")
      if (networkConfig.externalIP) {
        cachedExternalIP = networkConfig.externalIP
        callback(null, cachedExternalIP)
        return
      }
    }

    console.log("Note: Asking websites for WAN IP you could configure externalIP in config/network.json to skip this step.")
    externalIP((err, ip) => {
      if (err) {
        // Every service in the list has failed.
        callback(err, ip)
        return
      }

      cachedExternalIP = ip
      console.info("External IP is: " + cachedExternalIP)
      callback(null, cachedExternalIP)
    })
  },

  clearCache: function clearExternalIPCache() {
    cachedExternalIP = undefined
  }
}
