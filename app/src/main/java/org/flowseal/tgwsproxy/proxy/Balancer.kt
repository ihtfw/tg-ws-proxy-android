package org.flowseal.tgwsproxy.proxy

/**
 * Which Cloudflare proxy domain each DC uses (upstream proxy/balancer.py): one domain per DC,
 * picked at random, kept while it works, and the others tried in random order after it.
 */
class Balancer {
    @Volatile var domains: List<String> = emptyList()
        private set
    private val dcToDomain = HashMap<Int, String>()

    @Synchronized
    fun updateDomainsList(list: List<String>) {
        if (domains.sorted() == list.sorted()) return
        domains = list.toList()
        dcToDomain.clear()
        if (domains.isEmpty()) return
        for (dc in MtConst.CF_DCS) dcToDomain[dc] = domains.random()
    }

    /** True when the DC switched to [domain]. */
    @Synchronized
    fun updateDomainForDc(dc: Int, domain: String): Boolean {
        if (dcToDomain[dc] == domain) return false
        dcToDomain[dc] = domain
        return true
    }

    /** The DC's current domain first, then the rest shuffled. */
    @Synchronized
    fun domainsForDc(dc: Int): List<String> {
        val current = dcToDomain[dc]
        val out = ArrayList<String>()
        if (current != null) out.add(current)
        for (d in domains.shuffled()) if (d != current) out.add(d)
        return out
    }
}
