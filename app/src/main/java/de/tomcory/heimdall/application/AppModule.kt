package de.tomcory.heimdall.application

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.core.database.HeimdallDatabase
import de.tomcory.heimdall.core.datastore.PreferencesDataSource
import de.tomcory.heimdall.evaluator.Evaluator
import de.tomcory.heimdall.ui.scanner.ScannerRepository
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Singleton
    @Provides
    fun provideScannerRepository(
        preferences: PreferencesDataSource,
        database: HeimdallDatabase,
    ): ScannerRepository {
        return ScannerRepository(preferences, database)
    }

    @Provides
    fun provideEvaluator(
        database: HeimdallDatabase
    ): Evaluator {
        return Evaluator(database)
    }
}