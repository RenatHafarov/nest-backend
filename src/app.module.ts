import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AuthModule } from './auth/auth.module';
import { JwtAuthGuard } from './auth/guards/jwt-auth.guard';
import { PrismaModule } from './prisma/prisma.module';
import { UsersModule } from './users/users.module';
import { NftController } from './nft/nft.controller';
import { NftService } from './nft/nft.service';
import { NftcategoryController } from './nftcategory/nftcategory.controller';
import { NftcategoryService } from './nftcategory/nftcategory.service';
import { NftModule } from './nft/nft.module';
import { NftcategoryesModule } from './nftcategoryes/nftcategoryes.module';
import { NftcategoryesModule } from './nftcategoryes/nftcategoryes.module';
import { NftcategoryesService } from './nftcategoryes/nftcategoryes.service';
import { NftcategoryesController } from './nftcategoryes/nftcategoryes.controller';
import { NftcategoryModule } from './nftcategory/nftcategory.module';
import { NftcategoryesModule } from './nftcategoryes/nftcategoryes.module';


@Module({
    imports: [UsersModule, PrismaModule, AuthModule, ConfigModule.forRoot({ isGlobal: true }), NftModule, NftcategoryesModule, NftcategoryModule],
    providers: [
        {
            provide: APP_GUARD,
            useClass: JwtAuthGuard,
        },
        NftService,
        NftcategoryService,
        NftcategoryesService,
    ],
    controllers: [NftController, NftcategoryController, NftcategoryesController],
})
export class AppModule {}