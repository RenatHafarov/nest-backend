import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Staking } from '@prisma/client';

@Injectable()
export class StakingService {
  static map(arg0: (data: any) => { userId: any; nftCardId: any; amount: any; adminParameters: any; }) {
      throw new Error('Method not implemented.');
  }
  constructor(private prisma: PrismaService) { }

  async stake(userId: string, nftId: string, amount: string, adminParameters: Record<string, any>): Promise<void> {
    await this.prisma.staking.create({
      data: {
        userId,
        nftId,
        amount,
        adminParameters,
      },
    });

  }

  async History(nftId: string): Promise<Staking[]> {
    return this.prisma.staking.findMany({
      where: { nftId },
      orderBy: { createdAt: 'desc' },
    });
  }



}
