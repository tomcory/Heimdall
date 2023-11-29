package de.tomcory.heimdall.core.export.tex

import de.tomcory.heimdall.core.database.entity.Request
import de.tomcory.heimdall.core.database.entity.Response
import de.tomcory.heimdall.core.export.util.swapJsonQuotes
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

private fun findResponse(request: Request, responses: List<Response>): TexResponse {
    val response = responses.find { it.reqResId == request.reqResId }
    return if(response != null) {
        mapResponseToTex(response, request)
    } else {
        TexResponse(
            fromCache = false,
            initiator = request.initiatorPkg,
            method = request.method,
            parentFrameId = -1,
            requestId = request.reqResId.toString(),
            responseHeaders = listOf(),
            statusCode = 0,
            timeStamp = request.timestamp,
            url = "https://" + request.remoteHost + request.remotePath,
        )
    }
}

private fun mapResponseToTex(response: Response, request: Request) : TexResponse {
    return TexResponse(
        fromCache = false,
        initiator = response.initiatorPkg,
        method = request.method,
        parentFrameId = -1,
        requestId = response.reqResId.toString(),
        responseHeaders = headersJsonToHeadersList(response.headers),
        statusCode = response.statusCode,
        timeStamp = response.timestamp,
        ip = request.remoteIp,
        url = "https://" + request.remoteHost + request.remotePath,
    )
}

private fun mapRequestToTex(request: Request, responses: List<Response>) : TexRequest {
    val response = findResponse(request, responses)

    return TexRequest(
        initiator = request.initiatorPkg, // pkg, important
        method = request.method,
        requestId = request.reqResId.toString(),
        timeStamp = request.timestamp, // important
        url = "https://" + request.remoteHost + request.remotePath, // = remoteHost + path
        requestHeaders = headersJsonToHeadersList(request.headers),
        response = response,
        success = response.statusCode > 0, // true if response exists
    )
}

fun headersJsonToHeadersList(json: String): List<TexHeader> {

    val modifiedJson = swapJsonQuotes(json)

    val jsonObject = Json.parseToJsonElement(modifiedJson) as JsonObject
    val headersMap = mutableMapOf<String, String>()
    val encounteredNames = mutableSetOf<String>()

    for (entry in jsonObject.entries) {
        val name = entry.key
        val value = entry.value.toString()

        if (name in encounteredNames) {
            println("Warning: Duplicate header found for '$name'")
        } else {
            encounteredNames.add(name)
        }

        headersMap[name] = if(value.first() == '"' && value.last() == '"') value.substring(1 until value.length - 1) else value
    }

    return headersMap.map { (name, value) -> TexHeader(name, value) }
}