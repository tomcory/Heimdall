package de.tomcory.heimdall.core.datastore

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.Preferences
import javax.inject.Singleton

val Context.preferencesStore: DataStore<Preferences> by dataStore(
    fileName = "proto/preferences.proto",
    serializer = PreferencesSerializer
)

@Module
@InstallIn(SingletonComponent::class)
object DatastoreModule {
    @Singleton
    @Provides
    fun provideDatastore(@ApplicationContext context: Context): DataStore<Preferences> {
        return context.preferencesStore
    }
}