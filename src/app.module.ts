import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';

import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';

import { PrismaModule } from './prisma/prisma.module';

import { UsersModule } from './users/users.module';

import { NftController } from './nft/nft.controller';
import { NftService } from './nft/nft.service';
import { NftModule } from './nft/nft.module';

import { StackingModule } from './stacking/stacking.module';
import { StakingService } from './stacking/stacking.service';
import { StakingController } from './stacking/stacking.controller';

import { NftcategoryesService } from './nftcategoryes/nftcategoryes.service';
import { NftcategoryesController } from './nftcategoryes/nftcategoryes.controller';
import { NftcategoryesModule } from './nftcategoryes/nftcategoryes.module';
import { AutoStakingService } from './stacking/auto.stacking';


@Module({
    imports: [UsersModule, PrismaModule, AuthModule, ConfigModule.forRoot({ isGlobal: true }), NftModule, NftcategoryesModule,  StackingModule],
    providers: [
        {
            provide: APP_GUARD,
            useClass: JwtAuthGuard,
        },
        NftService,
        NftcategoryesService,
        StakingService,
        AutoStakingService
    ],
    controllers: [NftController, NftcategoryesController, NftcategoryesController, StakingController],
})
export class AppModule {}