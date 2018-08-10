// Check if there is a ban in place for an IP Address.

class Ban {
    async checkIP(ip) {
        //SELECT id, ip, reason, effective_from, expires FROM ban WHERE ip = {ip} AND effective_from > NOW() AND (expires IS NULL or NOW() < effective_from)
        return [];
    }

    async addIP(ip, reason, expires) {
        if (arguments.length == 2) {
            expires = reason;
            reason = '';
        }

        if (arguments.length == 1) {
            reason = '';
            expires = null;
        }
        // INSERT INTO ban (ip, reason, expires) VALUES ({ip}, {reason}, {expires})
    }

    async removeIP(ip) {
        // DELETE FROM ban WHERE ip = {ip}
    }

    async remove(id) {
        // DELETE FROM ban WHERE id = {id}
    }
}