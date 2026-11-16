package org.flowseal.tgwsproxy.service

/** Why the listening socket could not be opened (upstream utils/diagnostics.py). */
enum class ListenProblem { PORT_BUSY, PERMISSION, BAD_ADDRESS, OTHER }

/**
 * Maps a bind failure to what the user can do about it. Android reports errno names in the
 * message ("bind failed: EADDRINUSE (Address already in use)"), the desktop JVM only the text.
 */
fun diagnoseListenError(e: Throwable): ListenProblem {
    val text = generateSequence(e) { it.cause }
        .take(5)
        .mapNotNull { it.message }
        .joinToString(" ")
        .uppercase()
    return when {
        "EADDRINUSE" in text || "ADDRESS ALREADY IN USE" in text -> ListenProblem.PORT_BUSY
        "EACCES" in text || "PERMISSION DENIED" in text -> ListenProblem.PERMISSION
        "EADDRNOTAVAIL" in text || "CANNOT ASSIGN REQUESTED ADDRESS" in text || "EFAULT" in text ->
            ListenProblem.BAD_ADDRESS
        else -> ListenProblem.OTHER
    }
}
