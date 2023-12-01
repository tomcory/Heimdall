package de.tomcory.heimdall.core.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import androidx.datastore.dataStoreFile
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.Preferences
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import javax.inject.Singleton

private const val DATASTORE_NAME = "preferences"

@Module
@InstallIn(SingletonComponent::class)
object DatastoreModule {
    @Singleton
    @Provides
    fun provideDatastore(
        @ApplicationContext context: Context,
    ): DataStore<Preferences> {
        return DataStoreFactory.create(
            serializer = PreferencesSerializer,
            corruptionHandler = ReplaceFileCorruptionHandler {
                Preferences.getDefaultInstance()
            },
            scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
            produceFile = { context.dataStoreFile(DATASTORE_NAME) },
        )
    }

    @Singleton
    @Provides
    fun providePreferencesDataSource(
        datastore: DataStore<Preferences>
    ): PreferencesDataSource {
        return PreferencesDataSource(datastore)
    }
}