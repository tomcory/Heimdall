package de.tomcory.heimdall.application

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.dataStore
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.Preferences
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesSerializer
import javax.inject.Singleton

val Context.preferencesStore: DataStore<Preferences> by dataStore(
    fileName = "proto/preferences.proto",
    serializer = PreferencesSerializer
)

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Singleton
    @Provides
    fun provideHeimdallDatabase(@ApplicationContext context: Context): HeimdallDatabase {
        return Room.databaseBuilder(
            context,
            HeimdallDatabase::class.java, "heimdall"
        ).fallbackToDestructiveMigration().build()
    }
}