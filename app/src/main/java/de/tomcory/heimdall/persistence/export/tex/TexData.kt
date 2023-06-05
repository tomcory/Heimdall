package de.tomcory.heimdall.persistence.export.tex

import kotlinx.serialization.Serializable

@Serializable
data class TexRequest(
    val documentId: String? = null,
    val documentLifecycle: String? = null,
    val frameId: Int? = null,
    val frameType: String? = null,
    val initiator: String,
    val method: String,
    val parentFrameId: Int? = null,
    val requestId: String,
    val tabId: Int? = null,
    val timeStamp: Long,
    val type: String? = null,
    val url: String,
    val requestHeaders: List<TexHeader>,
    val response: TexResponse,
    val success: Boolean,
    val labels: List<TexLabel>? = null,
    val parentDocumentId: String? = null
)

@Serializable
data class TexHeader(
    val name: String,
    val value: String
)

@Serializable
data class TexResponse(
    val documentId: String? = null,
    val documentLifecycle: String? = null,
    val frameId: Int? = null,
    val frameType: String? = null,
    val fromCache: Boolean,
    val initiator: String,
    val ip: String? = null,
    val method: String,
    val parentFrameId: Int? = null,
    val requestId: String,
    val responseHeaders: List<TexHeader>,
    val statusCode: Int,
    val statusLine: String? = null,
    val tabId: Int? = null,
    val timeStamp: Long,
    val type: String? = null,
    val url: String,
    val parentDocumentId: String? = null
)

@Serializable
data class TexLabel(
    val isLabeled: Boolean,
    val blocklist: String,
    val rule: List<List<String>>
)