/*jshint esversion: 6 */

/*
 * A timer that attempts to be more accurate than native setInterval.
 * It calculates an appropriate delay to timeout after the callback is called.
 * It is intended that the Callback function return ASAP this will not handle async operations that may be delayed.
 */
class Interval {
    constructor(callback, rate = 1000, startNow = true, callNow = true) {
        this.id = null

        // TODO: Valdiate callback is function.

        this.callback = () => {
        if(this.running === false) return
            callback()
            this.id = setTimeout(this.callback, rate - (new Date() % rate))
        }

        if (startNow === true) {
            this.start(callNow)
        }
    }

    start(call_now = false) {
        if (this.running && call_now) {
            return this.callback()
        }

        this.running = true
        this.callback(call_now)
    }

    stop() {
        if(!this.running){
            return
        }

        this.running = false
        clearTimeout(this.id)
        this.id = null
    }

    trigger() {
        clearTimeout(this.id)
        this.callback(true)
    }
}

module.exports = Interval
