
import { Controller, Post, Body, Param, Get, UseGuards } from '@nestjs/common';
import { StakingService } from './stacking.service';
import { Role } from '@prisma/client';
import { Roles } from '@common/common/decorators';
import { RolesGuard } from 'src/auth/guards/roles.guard';


@Controller('staking')
export class StakingController {
    constructor(private readonly stakingService: StakingService) { }
    
    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Post()
    stake(@Body() data: { userId: string; nftCardId: string; amount: string; adminParameters: Record<string, any> }) {
        return this.stakingService.stake(data.userId, data.nftCardId, data.amount, data.adminParameters);
    }

    @UseGuards(RolesGuard)
    @Roles(Role.ADMIN)
    @Get(':nftid/history')
    getHistory(@Param('nftid') nftid: string) {
        return this.stakingService.History(nftid);
    }

}
