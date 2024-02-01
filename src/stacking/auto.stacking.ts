// src/staking/auto-staking.service.ts
import { Injectable } from '@nestjs/common';
import * as cron from 'node-cron';
import { PrismaService } from '../prisma/prisma.service';
import { StakingService } from './stacking.service';
import { Prisma } from '@prisma/client';


@Injectable()
export class AutoStakingService {
    constructor(
        private readonly prismaService: PrismaService,
        private readonly stakingService: StakingService,
    ) {

        cron.schedule('0 0 * * *', async () => {
            await this.autoStake();
        });
    }

    private async autoStake(): Promise<void> {
        try {
            const usersAndNftCardsToStake = await this.getUsersAndNftCardsToStake();
            
            for (const { userId, nftCardId, amount, adminParameters } of usersAndNftCardsToStake) {
                await this.stakingService.stake(userId, nftCardId, amount, adminParameters as Record<string, any>);
            }
        } catch (error) {
            console.error('Error during auto-staking:', error);
        }
    }

    private async getUsersAndNftCardsToStake(): Promise<Array<{ userId: string; nftCardId: string; amount: string; adminParameters: Prisma.JsonValue }>> {
        const stakingData = await this.prismaService.staking.findMany({
            where: { createdAt: { lte: new Date() } }
        });

        return stakingData.map((data) => ({
            userId: data.userId,
            nftCardId: data.nftId,
            amount: data.amount,
            adminParameters: data.adminParameters,
        }));
    }
}
