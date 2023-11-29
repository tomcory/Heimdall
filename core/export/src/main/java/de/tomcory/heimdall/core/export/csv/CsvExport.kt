package de.tomcory.heimdall.core.export.csv

import android.content.Context
import de.tomcory.heimdall.core.database.dao.RequestDao
import de.tomcory.heimdall.core.database.entity.Request
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

suspend fun exportRequestsToCSV(requestDao: RequestDao, context: Context, filename: String) {
    val csvFile = File(context.filesDir, filename)
    val limit = 1000
    var offset = 0
    var requests: List<Request>

    withContext(Dispatchers.IO) {
        csvFile.bufferedWriter().use { out ->
            out.write("id,timestamp,reqResId,headers,content,contentLength,method,remoteHost,remotePath,remoteIp,remotePort,localIp,localPort,initiatorId,initiatorPkg,isTracker\n")

            do {
                requests = requestDao.getAllPaginated(limit, offset)

                requests.forEach { request ->
                    out.write("${request.id},${request.timestamp},${request.reqResId},${request.headers},${request.content},${request.contentLength},${request.method},${request.remoteHost},${request.remotePath},${request.remoteIp},${request.remotePort},${request.localIp},${request.localPort},${request.initiatorId},${request.initiatorPkg},${request.isTracker}\n")
                }

                offset += limit
            } while (requests.isNotEmpty())
        }
    }
}

fun csvEscape(str: String): String {
    return if (str.contains(',')) {
        "\"" + str.replace("\"", "\"\"") + "\""
    } else {
        str
    }
}