package de.tomcory.heimdall.application

import android.content.Context
import androidx.room.Room
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.ui.scanner.traffic.TrafficScannerRepository
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Singleton
    @Provides
    fun provideTrafficScannerRepository(
        preferences: PreferencesDataSource,
        database: HeimdallDatabase,
    ): TrafficScannerRepository {
        return TrafficScannerRepository(preferences, database)
    }
}