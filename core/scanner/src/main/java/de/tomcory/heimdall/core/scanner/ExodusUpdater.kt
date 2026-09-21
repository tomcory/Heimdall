package de.tomcory.heimdall.core.scanner

import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.database.entity.Tracker
import retrofit2.Response
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.GET
import timber.log.Timber
import javax.inject.Inject


class ExodusUpdater @Inject constructor(
    private val database: HeimdallDatabase
) {

    suspend fun updateAll() {
        Timber.d("Querying Exodus API...")

        val result = try {
            val apiInstance = Retrofit.Builder()
                .baseUrl(ExodusAPIInterface.BASE_URL)
                .addConverterFactory(MoshiConverterFactory.create())
                .build()
                .create(ExodusAPIInterface::class.java)

            apiInstance.getAllTrackers()
        } catch (e: Exception) {
            Timber.e(e, "Failed to query Exodus API.")
            return
        }

        if (result.isSuccessful && result.body() != null) {
            Timber.d("Successfully queried Exodus API.")
            val trackersRaw = result.body()

            // the Exodus API's map key is the tracker's own stable id - keep it as our primary
            // key so repeat fetches upsert existing rows instead of reassigning ids (which used to
            // orphan AppXTracker associations on every refresh)
            val trackersById = trackersRaw?.trackers
                ?.mapNotNull { (key, raw) -> key.toLongOrNull()?.let { it to raw } }
                ?.toMap()
                ?: emptyMap()

            Timber.d("Updating database...")

            if (trackersById.isNotEmpty()) {
                val trackersWithRaw = trackersById.map { (id, raw) ->
                    Tracker(
                        id = id,
                        name = raw.name,
                        codeSignature = raw.code_signature,
                        networkSignature = raw.network_signature,
                        creationDate = raw.creation_date,
                        web = raw.website
                    ) to raw
                }

                database.trackerDao().insertTrackers(*trackersWithRaw.map { it.first }.toTypedArray())
                // remove trackers no longer present upstream; AppXTracker rows for them
                // cascade-delete via the foreign key
                database.trackerDao().deleteTrackersNotIn(trackersWithRaw.map { it.first.id })

                for ((tracker, raw) in trackersWithRaw) {
                    database.categoryDao().setCategoriesForTracker(tracker, raw.categories)
                }

                Timber.d("Database updated, ${trackersWithRaw.size} trackers added.")
            } else {
                Timber.w("Database not updated, no trackers found.")
            }

        } else {
            Timber.w("Failed to query Exodus API, response code: ${result.code()}.")
        }
    }
}

data class ExodusTracker(
    val categories: List<String> = emptyList(),
    val code_signature: String = String(),
    val creation_date: String = String(),
    val description: String = String(),
    val name: String = String(),
    val network_signature: String = String(),
    val website: String = String()
)

data class ExodusTrackers(
    val trackers: Map<String, ExodusTracker> = emptyMap()
)

interface ExodusAPIInterface {
    companion object {
        //TODO: fetch from preferences
        const val BASE_URL = "https://reports.exodus-privacy.eu.org/api/"
    }

    @GET("trackers")
    suspend fun getAllTrackers(): Response<ExodusTrackers>
}
