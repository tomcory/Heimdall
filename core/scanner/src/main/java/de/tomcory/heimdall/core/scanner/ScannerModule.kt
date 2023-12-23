package de.tomcory.heimdall.core.scanner

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import de.tomcory.heimdall.core.database.HeimdallDatabase

@Module
@InstallIn(SingletonComponent::class)
object ScannerModule {
    @Provides
    fun provideExodusUpdater(
        database: HeimdallDatabase
    ): ExodusUpdater {
        return ExodusUpdater(database)
    }
}