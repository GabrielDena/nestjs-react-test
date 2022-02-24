import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime'
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

	constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) { }

	async signup(dto: AuthDto) {
		// Generate password has
		const hash = await argon.hash(dto.password)

		// Save the new user in DB
		try {
			const user = await this.prisma.user.create({
				data: {
					email: dto.email,
					hash
				}
			})
	
			delete user.hash
	
			// return the sabed user
			return this.signToken(user.id, user.email)
		} catch(error) {
			if (error instanceof PrismaClientKnownRequestError) {
				if (error.code === 'P2002') {
					throw new ForbiddenException('E-mail já cadastrado')
				}
			}
			throw error
		}
	}

	async signin(dto: AuthDto) {

		// Find the user by email
		const user = await this.prisma.user.findUnique({
			where: {
				email: dto.email,
			}
		})
		// If not exist throw exception
		if (!user) throw new ForbiddenException ('Credenciais incorretas')

		// Compare password
		const pwMatches = await argon.verify(user.hash, dto.password)
		// If incorrect throw exception
		if (!pwMatches) throw new ForbiddenException ('Credenciais incorretas')

		// Send back the user
		delete user.hash
		return this.signToken(user.id, user.email)
	}

	async signToken(userId: number, email: string): Promise<{access_token: string}> {
		const payload = {
			sub: userId,
			email
		}
		const secret = this.config.get('JWT_Secret')
		const token = await this.jwt.signAsync(payload, {
			expiresIn: '15m',
			secret: secret,
		})

		return {
			access_token: token,
		}

	}
}