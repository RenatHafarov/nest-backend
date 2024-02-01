/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ({

/***/ "./libs/common/src/decorators/cookies.decorator.ts":
/*!*********************************************************!*\
  !*** ./libs/common/src/decorators/cookies.decorator.ts ***!
  \*********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Cookie = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.Cookie = (0, common_1.createParamDecorator)((key, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return key && key in request.cookies ? request.cookies[key] : key ? null : request.cookies;
});


/***/ }),

/***/ "./libs/common/src/decorators/current-user.decorator.ts":
/*!**************************************************************!*\
  !*** ./libs/common/src/decorators/current-user.decorator.ts ***!
  \**************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.CurrentUser = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.CurrentUser = (0, common_1.createParamDecorator)((key, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return key ? request.user[key] : request.user;
});


/***/ }),

/***/ "./libs/common/src/decorators/index.ts":
/*!*********************************************!*\
  !*** ./libs/common/src/decorators/index.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./is-passwords-matching-constraint.decorator.ts */ "./libs/common/src/decorators/is-passwords-matching-constraint.decorator.ts.ts"), exports);
__exportStar(__webpack_require__(/*! ./cookies.decorator */ "./libs/common/src/decorators/cookies.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./user-agent.decorator */ "./libs/common/src/decorators/user-agent.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./public.decorator */ "./libs/common/src/decorators/public.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./current-user.decorator */ "./libs/common/src/decorators/current-user.decorator.ts"), exports);
__exportStar(__webpack_require__(/*! ./roles.decorator */ "./libs/common/src/decorators/roles.decorator.ts"), exports);


/***/ }),

/***/ "./libs/common/src/decorators/is-passwords-matching-constraint.decorator.ts.ts":
/*!*************************************************************************************!*\
  !*** ./libs/common/src/decorators/is-passwords-matching-constraint.decorator.ts.ts ***!
  \*************************************************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IsPasswordsMatchingConstraint = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
let IsPasswordsMatchingConstraint = class IsPasswordsMatchingConstraint {
    validate(passwordRepeat, args) {
        const obj = args.object;
        return obj.password === passwordRepeat;
    }
    defaultMessage(validationArguments) {
        return 'Пароли не совпадают';
    }
};
exports.IsPasswordsMatchingConstraint = IsPasswordsMatchingConstraint;
exports.IsPasswordsMatchingConstraint = IsPasswordsMatchingConstraint = __decorate([
    (0, class_validator_1.ValidatorConstraint)({ name: 'IsPasswordsMatching', async: false })
], IsPasswordsMatchingConstraint);


/***/ }),

/***/ "./libs/common/src/decorators/public.decorator.ts":
/*!********************************************************!*\
  !*** ./libs/common/src/decorators/public.decorator.ts ***!
  \********************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.isPublic = exports.Public = exports.PUBLIC_KEY = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.PUBLIC_KEY = 'public';
const Public = () => (0, common_1.SetMetadata)(exports.PUBLIC_KEY, true);
exports.Public = Public;
const isPublic = (ctx, reflector) => {
    const isPublic = reflector.getAllAndOverride(exports.PUBLIC_KEY, [ctx.getHandler(), ctx.getClass()]);
    return isPublic;
};
exports.isPublic = isPublic;


/***/ }),

/***/ "./libs/common/src/decorators/roles.decorator.ts":
/*!*******************************************************!*\
  !*** ./libs/common/src/decorators/roles.decorator.ts ***!
  \*******************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.Roles = exports.ROLES_KEY = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.ROLES_KEY = 'roles';
const Roles = (...roles) => (0, common_1.SetMetadata)(exports.ROLES_KEY, roles);
exports.Roles = Roles;


/***/ }),

/***/ "./libs/common/src/decorators/user-agent.decorator.ts":
/*!************************************************************!*\
  !*** ./libs/common/src/decorators/user-agent.decorator.ts ***!
  \************************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserAgent = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
exports.UserAgent = (0, common_1.createParamDecorator)((_, ctx) => {
    const request = ctx.switchToHttp().getRequest();
    return request.headers['user-agent'];
});


/***/ }),

/***/ "./libs/common/src/utils/convert-to-seconds.ts":
/*!*****************************************************!*\
  !*** ./libs/common/src/utils/convert-to-seconds.ts ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.convertToSecondsUtil = void 0;
function convertToSecondsUtil(timeStr) {
    if (!isNaN(timeStr)) {
        return parseInt(timeStr);
    }
    let multiplier;
    switch (timeStr[timeStr.length - 1]) {
        case 's':
            multiplier = 1;
            break;
        case 'm':
            multiplier = 60;
            break;
        case 'h':
            multiplier = 60 * 60;
            break;
        case 'd':
            multiplier = 24 * 60 * 60;
            break;
        case 'M':
            multiplier = 30 * 24 * 60 * 60;
            break;
        case 'y':
            multiplier = 365 * 24 * 60 * 60;
            break;
        default:
            throw new Error('Invalid time string');
    }
    const num = parseInt(timeStr.slice(0, -1));
    return num * multiplier;
}
exports.convertToSecondsUtil = convertToSecondsUtil;


/***/ }),

/***/ "./libs/common/src/utils/index.ts":
/*!****************************************!*\
  !*** ./libs/common/src/utils/index.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./convert-to-seconds */ "./libs/common/src/utils/convert-to-seconds.ts"), exports);


/***/ }),

/***/ "./src/app.module.ts":
/*!***************************!*\
  !*** ./src/app.module.ts ***!
  \***************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AppModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const auth_module_1 = __webpack_require__(/*! ./auth/auth.module */ "./src/auth/auth.module.ts");
const jwt_auth_guard_1 = __webpack_require__(/*! ./auth/guards/jwt-auth.guard */ "./src/auth/guards/jwt-auth.guard.ts");
const prisma_module_1 = __webpack_require__(/*! ./prisma/prisma.module */ "./src/prisma/prisma.module.ts");
const users_module_1 = __webpack_require__(/*! ./users/users.module */ "./src/users/users.module.ts");
const nft_controller_1 = __webpack_require__(/*! ./nft/nft.controller */ "./src/nft/nft.controller.ts");
const nft_service_1 = __webpack_require__(/*! ./nft/nft.service */ "./src/nft/nft.service.ts");
const nft_module_1 = __webpack_require__(/*! ./nft/nft.module */ "./src/nft/nft.module.ts");
const stacking_module_1 = __webpack_require__(/*! ./stacking/stacking.module */ "./src/stacking/stacking.module.ts");
const stacking_service_1 = __webpack_require__(/*! ./stacking/stacking.service */ "./src/stacking/stacking.service.ts");
const stacking_controller_1 = __webpack_require__(/*! ./stacking/stacking.controller */ "./src/stacking/stacking.controller.ts");
const nftcategoryes_service_1 = __webpack_require__(/*! ./nftcategoryes/nftcategoryes.service */ "./src/nftcategoryes/nftcategoryes.service.ts");
const nftcategoryes_controller_1 = __webpack_require__(/*! ./nftcategoryes/nftcategoryes.controller */ "./src/nftcategoryes/nftcategoryes.controller.ts");
const nftcategoryes_module_1 = __webpack_require__(/*! ./nftcategoryes/nftcategoryes.module */ "./src/nftcategoryes/nftcategoryes.module.ts");
const auto_stacking_1 = __webpack_require__(/*! ./stacking/auto.stacking */ "./src/stacking/auto.stacking.ts");
let AppModule = class AppModule {
};
exports.AppModule = AppModule;
exports.AppModule = AppModule = __decorate([
    (0, common_1.Module)({
        imports: [users_module_1.UsersModule, prisma_module_1.PrismaModule, auth_module_1.AuthModule, config_1.ConfigModule.forRoot({ isGlobal: true }), nft_module_1.NftModule, nftcategoryes_module_1.NftcategoryesModule, stacking_module_1.StackingModule],
        providers: [
            {
                provide: core_1.APP_GUARD,
                useClass: jwt_auth_guard_1.JwtAuthGuard,
            },
            nft_service_1.NftService,
            nftcategoryes_service_1.NftcategoryesService,
            stacking_service_1.StakingService,
            auto_stacking_1.AutoStakingService
        ],
        controllers: [nft_controller_1.NftController, nftcategoryes_controller_1.NftcategoryesController, nftcategoryes_controller_1.NftcategoryesController, stacking_controller_1.StakingController],
    })
], AppModule);


/***/ }),

/***/ "./src/auth/auth.controller.ts":
/*!*************************************!*\
  !*** ./src/auth/auth.controller.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthController = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const common_2 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const express_1 = __webpack_require__(/*! express */ "express");
const responses_1 = __webpack_require__(/*! src/users/responses */ "./src/users/responses/index.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./src/auth/auth.service.ts");
const dto_1 = __webpack_require__(/*! ./dto */ "./src/auth/dto/index.ts");
const REFRESH_TOKEN = 'refreshtoken';
let AuthController = class AuthController {
    constructor(authService, configService) {
        this.authService = authService;
        this.configService = configService;
    }
    async register(dto) {
        const user = await this.authService.register(dto);
        if (!user) {
            throw new common_1.BadRequestException(`Не получаеться зарегистрировать пользователя с данными ${JSON.stringify(dto)}`);
        }
        return new responses_1.UserResponse(user);
    }
    async login(dto, res, agent) {
        const tokens = await this.authService.login(dto, agent);
        if (!tokens) {
            throw new common_1.BadRequestException(`Не получаеться войти с данными ${JSON.stringify(dto)}`);
        }
        this.setRefreshTokenToCokies(tokens, res);
        return { accessToken: (tokens.accessToken) };
    }
    async logout(refreshToken, res) {
        if (!refreshToken) {
            res.sendStatus(common_1.HttpStatus.OK);
            return;
        }
        await this.authService.deleteRefreshToken(refreshToken);
        res.cookie(REFRESH_TOKEN, '', { httpOnly: true, secure: true, expires: new Date() });
        res.sendStatus(common_1.HttpStatus.OK);
    }
    async refreshTokens(refreshToken, res, agent) {
        if (!refreshToken) {
            throw new common_1.UnauthorizedException();
        }
        const tokens = await this.authService.refreshTokens(refreshToken, agent);
        if (!tokens) {
            throw new common_1.UnauthorizedException();
        }
        this.setRefreshTokenToCokies(tokens, res);
    }
    setRefreshTokenToCokies(tokens, res) {
        if (!tokens) {
            throw new common_1.UnauthorizedException();
        }
        res.cookie(REFRESH_TOKEN, tokens.refreshToken.token, {
            httpOnly: true,
            sameSite: 'lax',
            expires: new Date(tokens.refreshToken.exp),
            secure: this.configService.get('NODE_ENV', 'development') === 'production',
            path: '/'
        });
        res.status(common_1.HttpStatus.CREATED).json({ accesstokens: tokens.accessToken });
    }
};
exports.AuthController = AuthController;
__decorate([
    (0, common_1.UseInterceptors)(common_1.ClassSerializerInterceptor),
    (0, common_2.Post)('register'),
    __param(0, (0, common_2.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof dto_1.RegisterDto !== "undefined" && dto_1.RegisterDto) === "function" ? _c : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "register", null);
__decorate([
    (0, common_2.Post)('login'),
    __param(0, (0, common_2.Body)()),
    __param(1, (0, common_1.Res)()),
    __param(2, (0, decorators_1.UserAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_d = typeof dto_1.LoginDto !== "undefined" && dto_1.LoginDto) === "function" ? _d : Object, typeof (_e = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _e : Object, String]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "login", null);
__decorate([
    (0, common_2.Get)('logout'),
    __param(0, (0, decorators_1.Cookie)(REFRESH_TOKEN)),
    __param(1, (0, common_1.Res)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_f = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _f : Object]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "logout", null);
__decorate([
    (0, common_2.Get)('refresh-tokens'),
    __param(0, (0, decorators_1.Cookie)(REFRESH_TOKEN)),
    __param(1, (0, common_1.Res)()),
    __param(2, (0, decorators_1.UserAgent)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof express_1.Response !== "undefined" && express_1.Response) === "function" ? _g : Object, String]),
    __metadata("design:returntype", Promise)
], AuthController.prototype, "refreshTokens", null);
exports.AuthController = AuthController = __decorate([
    (0, decorators_1.Public)(),
    (0, common_2.Controller)('auth'),
    __metadata("design:paramtypes", [typeof (_a = typeof auth_service_1.AuthService !== "undefined" && auth_service_1.AuthService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], AuthController);


/***/ }),

/***/ "./src/auth/auth.module.ts":
/*!*********************************!*\
  !*** ./src/auth/auth.module.ts ***!
  \*********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const users_module_1 = __webpack_require__(/*! src/users/users.module */ "./src/users/users.module.ts");
const auth_controller_1 = __webpack_require__(/*! ./auth.controller */ "./src/auth/auth.controller.ts");
const auth_service_1 = __webpack_require__(/*! ./auth.service */ "./src/auth/auth.service.ts");
const config_1 = __webpack_require__(/*! ./config */ "./src/auth/config/index.ts");
const guards_1 = __webpack_require__(/*! ./guards */ "./src/auth/guards/index.ts");
const strategies_1 = __webpack_require__(/*! ./strategies */ "./src/auth/strategies/index.ts");
let AuthModule = class AuthModule {
};
exports.AuthModule = AuthModule;
exports.AuthModule = AuthModule = __decorate([
    (0, common_1.Module)({
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, ...strategies_1.STRATEGIE, ...guards_1.GUARDS],
        imports: [passport_1.PassportModule, jwt_1.JwtModule.registerAsync((0, config_1.options)()), users_module_1.UsersModule]
    })
], AuthModule);


/***/ }),

/***/ "./src/auth/auth.service.ts":
/*!**********************************!*\
  !*** ./src/auth/auth.service.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var AuthService_1;
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const jwt_1 = __webpack_require__(/*! @nestjs/jwt */ "@nestjs/jwt");
const bcrypt_1 = __webpack_require__(/*! bcrypt */ "bcrypt");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const users_service_1 = __webpack_require__(/*! src/users/users.service */ "./src/users/users.service.ts");
const uuid_1 = __webpack_require__(/*! uuid */ "uuid");
const date_fns_1 = __webpack_require__(/*! date-fns */ "date-fns");
let AuthService = AuthService_1 = class AuthService {
    constructor(userService, jwtService, prismaService) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.prismaService = prismaService;
        this.logger = new common_1.Logger(AuthService_1.name);
    }
    async register(dto) {
        const user = await this.userService.findOne(dto.email).catch(err => {
            this.logger.error(err);
            return null;
        });
        if (user) {
            throw new common_1.ConflictException('Пользователь с таким email уже зарегистрирован.');
        }
        return this.userService.createUser(dto).catch(err => {
            this.logger.error(err);
            return null;
        });
    }
    async refreshTokens(refreshToken, agent) {
        const token = await this.prismaService.token.findFirst({ where: { token: refreshToken } });
        if (!token) {
            throw new common_1.UnauthorizedException();
        }
        await this.prismaService.token.delete({ where: { token: refreshToken } });
        if (new Date(token.exp) < new Date()) {
            throw new common_1.UnauthorizedException();
        }
        await this.prismaService.token.delete({ where: { token: refreshToken } });
        const user = await this.userService.findOne(token.userId);
        return this.generateTokens(user, agent);
    }
    async login(dto, agent) {
        const user = await this.userService.findOne(dto.email, true).catch(err => {
            this.logger.error(err);
            return null;
        });
        if (!user || !(0, bcrypt_1.compareSync)(dto.password, user.password)) {
            throw new common_1.UnauthorizedException('Не верный логин или пороль');
        }
        return this.generateTokens(user, agent);
    }
    async deleteRefreshToken(token) {
        return this.prismaService.token.delete({ where: { token } });
    }
    async generateTokens(user, agent) {
        const accessToken = 'Bearer ' + this.jwtService.sign({ id: user.id, email: user.email, roles: user.roles });
        const refreshToken = await this.getRefreshToken(user.id, agent);
        return { accessToken, refreshToken };
    }
    async getRefreshToken(userId, agent) {
        const _token = await this.prismaService.token.findFirst({
            where: {
                userId,
                userAgent: agent
            }
        });
        const token = _token?.token ?? '';
        return this.prismaService.token.upsert({
            where: { token },
            update: {
                token: (0, uuid_1.v4)(),
                exp: (0, date_fns_1.add)(new Date(), { months: 1 }),
            },
            create: {
                token: (0, uuid_1.v4)(),
                exp: (0, date_fns_1.add)(new Date(), { months: 1 }),
                userId,
                userAgent: agent,
            }
        });
    }
};
exports.AuthService = AuthService;
exports.AuthService = AuthService = AuthService_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof jwt_1.JwtService !== "undefined" && jwt_1.JwtService) === "function" ? _b : Object, typeof (_c = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _c : Object])
], AuthService);


/***/ }),

/***/ "./src/auth/config/index.ts":
/*!**********************************!*\
  !*** ./src/auth/config/index.ts ***!
  \**********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./jwt-module-async-options */ "./src/auth/config/jwt-module-async-options.ts"), exports);


/***/ }),

/***/ "./src/auth/config/jwt-module-async-options.ts":
/*!*****************************************************!*\
  !*** ./src/auth/config/jwt-module-async-options.ts ***!
  \*****************************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.options = void 0;
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const jwtModuleOptions = (config) => ({
    secret: config.get('JWT_SECRET'),
    signOptions: {
        expiresIn: config.get('JWT_EXP', '5m'),
    },
});
const options = () => ({
    inject: [config_1.ConfigService],
    useFactory: (config) => jwtModuleOptions(config),
});
exports.options = options;


/***/ }),

/***/ "./src/auth/dto/index.ts":
/*!*******************************!*\
  !*** ./src/auth/dto/index.ts ***!
  \*******************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./register.dto */ "./src/auth/dto/register.dto.ts"), exports);
__exportStar(__webpack_require__(/*! ./login.dto */ "./src/auth/dto/login.dto.ts"), exports);


/***/ }),

/***/ "./src/auth/dto/login.dto.ts":
/*!***********************************!*\
  !*** ./src/auth/dto/login.dto.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.LoginDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class LoginDto {
}
exports.LoginDto = LoginDto;
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], LoginDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], LoginDto.prototype, "password", void 0);


/***/ }),

/***/ "./src/auth/dto/register.dto.ts":
/*!**************************************!*\
  !*** ./src/auth/dto/register.dto.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RegisterDto = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class RegisterDto {
}
exports.RegisterDto = RegisterDto;
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsEmail)(),
    __metadata("design:type", String)
], RegisterDto.prototype, "email", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(6),
    __metadata("design:type", String)
], RegisterDto.prototype, "password", void 0);
__decorate([
    (0, class_validator_1.IsNotEmpty)(),
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.MinLength)(6),
    (0, class_validator_1.Validate)(decorators_1.IsPasswordsMatchingConstraint),
    __metadata("design:type", String)
], RegisterDto.prototype, "passwordRepeat", void 0);


/***/ }),

/***/ "./src/auth/guards/index.ts":
/*!**********************************!*\
  !*** ./src/auth/guards/index.ts ***!
  \**********************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.GUARDS = void 0;
const jwt_auth_guard_1 = __webpack_require__(/*! ./jwt-auth.guard */ "./src/auth/guards/jwt-auth.guard.ts");
const roles_guard_1 = __webpack_require__(/*! ./roles.guard */ "./src/auth/guards/roles.guard.ts");
exports.GUARDS = [jwt_auth_guard_1.JwtAuthGuard, roles_guard_1.RolesGuard];


/***/ }),

/***/ "./src/auth/guards/jwt-auth.guard.ts":
/*!*******************************************!*\
  !*** ./src/auth/guards/jwt-auth.guard.ts ***!
  \*******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtAuthGuard = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
let JwtAuthGuard = class JwtAuthGuard extends (0, passport_1.AuthGuard)('jwt') {
    constructor(reflector) {
        super();
        this.reflector = reflector;
    }
    canActivate(ctx) {
        const _isPublic = (0, decorators_1.isPublic)(ctx, this.reflector);
        if (_isPublic) {
            return true;
        }
        return super.canActivate(ctx);
    }
};
exports.JwtAuthGuard = JwtAuthGuard;
exports.JwtAuthGuard = JwtAuthGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], JwtAuthGuard);


/***/ }),

/***/ "./src/auth/guards/roles.guard.ts":
/*!****************************************!*\
  !*** ./src/auth/guards/roles.guard.ts ***!
  \****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.RolesGuard = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
let RolesGuard = class RolesGuard {
    constructor(reflector) {
        this.reflector = reflector;
    }
    canActivate(context) {
        const requiredRoles = this.reflector.getAllAndOverride(decorators_1.ROLES_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);
        if (!requiredRoles) {
            return true;
        }
        const { user } = context.switchToHttp().getRequest();
        return requiredRoles.some((role) => user.roles?.includes(role));
    }
};
exports.RolesGuard = RolesGuard;
exports.RolesGuard = RolesGuard = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof core_1.Reflector !== "undefined" && core_1.Reflector) === "function" ? _a : Object])
], RolesGuard);


/***/ }),

/***/ "./src/auth/interfaces.ts":
/*!********************************!*\
  !*** ./src/auth/interfaces.ts ***!
  \********************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));


/***/ }),

/***/ "./src/auth/strategies/index.ts":
/*!**************************************!*\
  !*** ./src/auth/strategies/index.ts ***!
  \**************************************/
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.STRATEGIE = void 0;
const jwt_strategy_1 = __webpack_require__(/*! ./jwt.strategy */ "./src/auth/strategies/jwt.strategy.ts");
exports.STRATEGIE = [jwt_strategy_1.JwtStrategy];


/***/ }),

/***/ "./src/auth/strategies/jwt.strategy.ts":
/*!*********************************************!*\
  !*** ./src/auth/strategies/jwt.strategy.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var JwtStrategy_1;
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.JwtStrategy = void 0;
const passport_jwt_1 = __webpack_require__(/*! passport-jwt */ "passport-jwt");
const passport_1 = __webpack_require__(/*! @nestjs/passport */ "@nestjs/passport");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const users_service_1 = __webpack_require__(/*! src/users/users.service */ "./src/users/users.service.ts");
let JwtStrategy = JwtStrategy_1 = class JwtStrategy extends (0, passport_1.PassportStrategy)(passport_jwt_1.Strategy) {
    constructor(configService, userService) {
        super({
            jwtFromRequest: passport_jwt_1.ExtractJwt.fromAuthHeaderAsBearerToken(),
            ignoreExpiration: false,
            secretOrKey: configService.get('JWT_SECRET'),
        });
        this.configService = configService;
        this.userService = userService;
        this.logger = new common_1.Logger(JwtStrategy_1.name);
    }
    async validate(payload) {
        const user = await this.userService.findOne(payload.id).catch(err => {
            this.logger.error(err);
            return null;
        });
        if (!user) {
            throw new common_1.UnauthorizedException();
        }
        return payload;
    }
};
exports.JwtStrategy = JwtStrategy;
exports.JwtStrategy = JwtStrategy = JwtStrategy_1 = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _a : Object, typeof (_b = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _b : Object])
], JwtStrategy);


/***/ }),

/***/ "./src/nft/nft.controller.ts":
/*!***********************************!*\
  !*** ./src/nft/nft.controller.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftController = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const roles_guard_1 = __webpack_require__(/*! src/auth/guards/roles.guard */ "./src/auth/guards/roles.guard.ts");
const nft_service_1 = __webpack_require__(/*! ./nft.service */ "./src/nft/nft.service.ts");
const interfaces_1 = __webpack_require__(/*! src/auth/interfaces */ "./src/auth/interfaces.ts");
const nft_dto_1 = __webpack_require__(/*! ./nft.dto */ "./src/nft/nft.dto.ts");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
let NftController = class NftController {
    constructor(nftService, prismaService) {
        this.nftService = nftService;
        this.prismaService = prismaService;
    }
    async findAll() {
        return this.prismaService.nft.findMany();
    }
    async find(filters) {
        return this.nftService.find(filters);
    }
    async createNft(dto, user) {
        return this.nftService.createNft(dto, user);
    }
    async editNft(id, user, dto) {
        return this.nftService.editNft(id, user, dto);
    }
    async deleteNft(id, user) {
        return this.nftService.deleteNft(id, user);
    }
};
exports.NftController = NftController;
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], NftController.prototype, "findAll", null);
__decorate([
    (0, common_1.Get)(),
    __param(0, (0, common_1.Query)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", Promise)
], NftController.prototype, "find", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Post)(),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof nft_dto_1.CreateNftDto !== "undefined" && nft_dto_1.CreateNftDto) === "function" ? _c : Object, typeof (_d = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], NftController.prototype, "createNft", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Post)(':id'),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_e = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _e : Object, typeof (_f = typeof nft_dto_1.EditNftDto !== "undefined" && nft_dto_1.EditNftDto) === "function" ? _f : Object]),
    __metadata("design:returntype", Promise)
], NftController.prototype, "editNft", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], NftController.prototype, "deleteNft", null);
exports.NftController = NftController = __decorate([
    (0, common_1.Controller)('nft'),
    __metadata("design:paramtypes", [typeof (_a = typeof nft_service_1.NftService !== "undefined" && nft_service_1.NftService) === "function" ? _a : Object, typeof (_b = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _b : Object])
], NftController);


/***/ }),

/***/ "./src/nft/nft.dto.ts":
/*!****************************!*\
  !*** ./src/nft/nft.dto.ts ***!
  \****************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EditNftDto = exports.CreateNftDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CreateNftDto {
}
exports.CreateNftDto = CreateNftDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateNftDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateNftDto.prototype, "price", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateNftDto.prototype, "categoryes", void 0);
__decorate([
    (0, class_validator_1.IsNumber)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", Number)
], CreateNftDto.prototype, "stacking", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateNftDto.prototype, "descripton", void 0);
class EditNftDto {
}
exports.EditNftDto = EditNftDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], EditNftDto.prototype, "price", void 0);
__decorate([
    (0, class_validator_1.IsInt)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", Number)
], EditNftDto.prototype, "stacking", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], EditNftDto.prototype, "categoryes", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], EditNftDto.prototype, "description", void 0);


/***/ }),

/***/ "./src/nft/nft.module.ts":
/*!*******************************!*\
  !*** ./src/nft/nft.module.ts ***!
  \*******************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let NftModule = class NftModule {
};
exports.NftModule = NftModule;
exports.NftModule = NftModule = __decorate([
    (0, common_1.Module)({})
], NftModule);


/***/ }),

/***/ "./src/nft/nft.service.ts":
/*!********************************!*\
  !*** ./src/nft/nft.service.ts ***!
  \********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const stacking_service_1 = __webpack_require__(/*! src/stacking/stacking.service */ "./src/stacking/stacking.service.ts");
let NftService = class NftService {
    constructor(prismaService, stakingService) {
        this.prismaService = prismaService;
        this.stakingService = stakingService;
    }
    async createNft(nft, user) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        this.prismaService.category.create({
            data: {
                name: nft.categoryes,
                nftid: nft.nftId
            }
        });
        return this.prismaService.nft.create({
            data: {
                name: nft.name,
                categoryes: nft.categoryes,
                description: nft.description,
                stacking: nft.stacking
            }
        });
    }
    async find(filters) {
        return this.prismaService.nft.findMany({
            where: filters,
        });
    }
    async editNft(id, user, dto) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        const nft = await this.prismaService.nft.findFirst({ where: { nftId: id } });
        if (!nft) {
            throw new common_1.BadRequestException();
        }
        return this.prismaService.nft.update({
            where: { nftId: id },
            data: dto,
        });
    }
    async deleteNft(nftid, user) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        return this.prismaService.nft.delete({ where: { nftId: nftid } });
    }
    async stake(userId, nftCardId, amount, adminParameters) {
        const nftCard = await this.prismaService.nft.findUnique({ where: { nftId: nftCardId } });
        if (!nftCard) {
            throw new Error('NFT card not found');
        }
        await this.stakingService.stake(userId, nftCardId, amount, adminParameters);
    }
};
exports.NftService = NftService;
exports.NftService = NftService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object, typeof (_b = typeof stacking_service_1.StakingService !== "undefined" && stacking_service_1.StakingService) === "function" ? _b : Object])
], NftService);


/***/ }),

/***/ "./src/nftcategoryes/nftcategoryes.controller.ts":
/*!*******************************************************!*\
  !*** ./src/nftcategoryes/nftcategoryes.controller.ts ***!
  \*******************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c, _d, _e, _f, _g;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftcategoryesController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const nftcategoryes_service_1 = __webpack_require__(/*! ./nftcategoryes.service */ "./src/nftcategoryes/nftcategoryes.service.ts");
const roles_guard_1 = __webpack_require__(/*! src/auth/guards/roles.guard */ "./src/auth/guards/roles.guard.ts");
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const nftcategoryes_dto_1 = __webpack_require__(/*! ./nftcategoryes.dto */ "./src/nftcategoryes/nftcategoryes.dto.ts");
const interfaces_1 = __webpack_require__(/*! src/auth/interfaces */ "./src/auth/interfaces.ts");
let NftcategoryesController = class NftcategoryesController {
    constructor(categoryesService, prismaService) {
        this.categoryesService = categoryesService;
        this.prismaService = prismaService;
    }
    async findAll() {
        return this.prismaService.category.findMany();
    }
    async createCategory(dto, user) {
        return this.categoryesService.createCategory(dto, user);
    }
    async editCategory(id, user, dto) {
        return this.categoryesService.editCateory(id, user, dto);
    }
    async deleteCategory(id, user) {
        return this.categoryesService.deleteCaregory(id, user);
    }
};
exports.NftcategoryesController = NftcategoryesController;
__decorate([
    (0, common_1.Get)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], NftcategoryesController.prototype, "findAll", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Post)(),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof nftcategoryes_dto_1.CreateCategoryDto !== "undefined" && nftcategoryes_dto_1.CreateCategoryDto) === "function" ? _c : Object, typeof (_d = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _d : Object]),
    __metadata("design:returntype", Promise)
], NftcategoryesController.prototype, "createCategory", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Post)(':id'),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_e = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _e : Object, typeof (_f = typeof nftcategoryes_dto_1.EditCategoryDto !== "undefined" && nftcategoryes_dto_1.EditCategoryDto) === "function" ? _f : Object]),
    __metadata("design:returntype", Promise)
], NftcategoryesController.prototype, "editCategory", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_g = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _g : Object]),
    __metadata("design:returntype", Promise)
], NftcategoryesController.prototype, "deleteCategory", null);
exports.NftcategoryesController = NftcategoryesController = __decorate([
    (0, common_1.Controller)('nftcategoryes'),
    __metadata("design:paramtypes", [typeof (_a = typeof nftcategoryes_service_1.NftcategoryesService !== "undefined" && nftcategoryes_service_1.NftcategoryesService) === "function" ? _a : Object, typeof (_b = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _b : Object])
], NftcategoryesController);


/***/ }),

/***/ "./src/nftcategoryes/nftcategoryes.dto.ts":
/*!************************************************!*\
  !*** ./src/nftcategoryes/nftcategoryes.dto.ts ***!
  \************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.EditCategoryDto = exports.CreateCategoryDto = void 0;
const class_validator_1 = __webpack_require__(/*! class-validator */ "class-validator");
class CreateCategoryDto {
}
exports.CreateCategoryDto = CreateCategoryDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateCategoryDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsNotEmpty)(),
    __metadata("design:type", String)
], CreateCategoryDto.prototype, "nftid", void 0);
class EditCategoryDto {
}
exports.EditCategoryDto = EditCategoryDto;
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], EditCategoryDto.prototype, "name", void 0);
__decorate([
    (0, class_validator_1.IsString)(),
    (0, class_validator_1.IsOptional)(),
    __metadata("design:type", String)
], EditCategoryDto.prototype, "nftid", void 0);


/***/ }),

/***/ "./src/nftcategoryes/nftcategoryes.module.ts":
/*!***************************************************!*\
  !*** ./src/nftcategoryes/nftcategoryes.module.ts ***!
  \***************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftcategoryesModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let NftcategoryesModule = class NftcategoryesModule {
};
exports.NftcategoryesModule = NftcategoryesModule;
exports.NftcategoryesModule = NftcategoryesModule = __decorate([
    (0, common_1.Module)({})
], NftcategoryesModule);


/***/ }),

/***/ "./src/nftcategoryes/nftcategoryes.service.ts":
/*!****************************************************!*\
  !*** ./src/nftcategoryes/nftcategoryes.service.ts ***!
  \****************************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.NftcategoryesService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
let NftcategoryesService = class NftcategoryesService {
    constructor(prismaService) {
        this.prismaService = prismaService;
    }
    async createCategory(dto, user) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        return this.prismaService.category.create({
            data: {
                name: dto.name,
                nftid: dto.nftid
            }
        });
    }
    async editCateory(id, user, dto) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        const nft = await this.prismaService.category.findFirst({ where: { id: id } });
        if (!nft) {
            throw new common_1.BadRequestException();
        }
        return this.prismaService.category.update({
            where: { id: id },
            data: dto,
        });
    }
    async deleteCaregory(id, user) {
        if (!user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        return this.prismaService.category.delete({ where: { id: id } });
    }
};
exports.NftcategoryesService = NftcategoryesService;
exports.NftcategoryesService = NftcategoryesService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object])
], NftcategoryesService);


/***/ }),

/***/ "./src/prisma/prisma.module.ts":
/*!*************************************!*\
  !*** ./src/prisma/prisma.module.ts ***!
  \*************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PrismaModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! ./prisma.service */ "./src/prisma/prisma.service.ts");
let PrismaModule = class PrismaModule {
};
exports.PrismaModule = PrismaModule;
exports.PrismaModule = PrismaModule = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({
        providers: [prisma_service_1.PrismaService],
        exports: [prisma_service_1.PrismaService]
    })
], PrismaModule);


/***/ }),

/***/ "./src/prisma/prisma.service.ts":
/*!**************************************!*\
  !*** ./src/prisma/prisma.service.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.PrismaService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
let PrismaService = class PrismaService extends client_1.PrismaClient {
    async onModuleInit() {
        await this.$connect();
    }
};
exports.PrismaService = PrismaService;
exports.PrismaService = PrismaService = __decorate([
    (0, common_1.Injectable)()
], PrismaService);


/***/ }),

/***/ "./src/stacking/auto.stacking.ts":
/*!***************************************!*\
  !*** ./src/stacking/auto.stacking.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AutoStakingService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const cron = __webpack_require__(/*! node-cron */ "node-cron");
const prisma_service_1 = __webpack_require__(/*! ../prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const stacking_service_1 = __webpack_require__(/*! ./stacking.service */ "./src/stacking/stacking.service.ts");
let AutoStakingService = class AutoStakingService {
    constructor(prismaService, stakingService) {
        this.prismaService = prismaService;
        this.stakingService = stakingService;
        cron.schedule('0 0 * * *', async () => {
            await this.autoStake();
        });
    }
    async autoStake() {
        try {
            const usersAndNftCardsToStake = await this.getUsersAndNftCardsToStake();
            for (const { userId, nftCardId, amount, adminParameters } of usersAndNftCardsToStake) {
                await this.stakingService.stake(userId, nftCardId, amount, adminParameters);
            }
        }
        catch (error) {
            console.error('Error during auto-staking:', error);
        }
    }
    async getUsersAndNftCardsToStake() {
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
};
exports.AutoStakingService = AutoStakingService;
exports.AutoStakingService = AutoStakingService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object, typeof (_b = typeof stacking_service_1.StakingService !== "undefined" && stacking_service_1.StakingService) === "function" ? _b : Object])
], AutoStakingService);


/***/ }),

/***/ "./src/stacking/stacking.controller.ts":
/*!*********************************************!*\
  !*** ./src/stacking/stacking.controller.ts ***!
  \*********************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StakingController = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const stacking_service_1 = __webpack_require__(/*! ./stacking.service */ "./src/stacking/stacking.service.ts");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const roles_guard_1 = __webpack_require__(/*! src/auth/guards/roles.guard */ "./src/auth/guards/roles.guard.ts");
let StakingController = class StakingController {
    constructor(stakingService) {
        this.stakingService = stakingService;
    }
    stake(data) {
        return this.stakingService.stake(data.userId, data.nftCardId, data.amount, data.adminParameters);
    }
    getHistory(nftid) {
        return this.stakingService.History(nftid);
    }
};
exports.StakingController = StakingController;
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Post)(),
    __param(0, (0, common_1.Body)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [Object]),
    __metadata("design:returntype", void 0)
], StakingController.prototype, "stake", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Get)(':nftid/history'),
    __param(0, (0, common_1.Param)('nftid')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", void 0)
], StakingController.prototype, "getHistory", null);
exports.StakingController = StakingController = __decorate([
    (0, common_1.Controller)('staking'),
    __metadata("design:paramtypes", [typeof (_a = typeof stacking_service_1.StakingService !== "undefined" && stacking_service_1.StakingService) === "function" ? _a : Object])
], StakingController);


/***/ }),

/***/ "./src/stacking/stacking.module.ts":
/*!*****************************************!*\
  !*** ./src/stacking/stacking.module.ts ***!
  \*****************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StackingModule = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
let StackingModule = class StackingModule {
};
exports.StackingModule = StackingModule;
exports.StackingModule = StackingModule = __decorate([
    (0, common_1.Module)({})
], StackingModule);


/***/ }),

/***/ "./src/stacking/stacking.service.ts":
/*!******************************************!*\
  !*** ./src/stacking/stacking.service.ts ***!
  \******************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.StakingService = void 0;
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! ../prisma/prisma.service */ "./src/prisma/prisma.service.ts");
let StakingService = class StakingService {
    static map(arg0) {
        throw new Error('Method not implemented.');
    }
    constructor(prisma) {
        this.prisma = prisma;
    }
    async stake(userId, nftId, amount, adminParameters) {
        await this.prisma.staking.create({
            data: {
                userId,
                nftId,
                amount,
                adminParameters,
            },
        });
    }
    async History(nftId) {
        return this.prisma.staking.findMany({
            where: { nftId },
            orderBy: { createdAt: 'desc' },
        });
    }
};
exports.StakingService = StakingService;
exports.StakingService = StakingService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object])
], StakingService);


/***/ }),

/***/ "./src/users/responses/index.ts":
/*!**************************************!*\
  !*** ./src/users/responses/index.ts ***!
  \**************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
__exportStar(__webpack_require__(/*! ./user.respons */ "./src/users/responses/user.respons.ts"), exports);


/***/ }),

/***/ "./src/users/responses/user.respons.ts":
/*!*********************************************!*\
  !*** ./src/users/responses/user.respons.ts ***!
  \*********************************************/
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UserResponse = void 0;
class UserResponse {
    constructor(user) { Object.assign(this, user); }
}
exports.UserResponse = UserResponse;


/***/ }),

/***/ "./src/users/users.controller.ts":
/*!***************************************!*\
  !*** ./src/users/users.controller.ts ***!
  \***************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersController = void 0;
const decorators_1 = __webpack_require__(/*! @common/common/decorators */ "./libs/common/src/decorators/index.ts");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const roles_guard_1 = __webpack_require__(/*! src/auth/guards/roles.guard */ "./src/auth/guards/roles.guard.ts");
const interfaces_1 = __webpack_require__(/*! src/auth/interfaces */ "./src/auth/interfaces.ts");
const responses_1 = __webpack_require__(/*! ./responses */ "./src/users/responses/index.ts");
const users_service_1 = __webpack_require__(/*! ./users.service */ "./src/users/users.service.ts");
let UsersController = class UsersController {
    constructor(usersService) {
        this.usersService = usersService;
    }
    async findOneUser(idOrEmail) {
        const user = await this.usersService.findOne(idOrEmail);
        return new responses_1.UserResponse(user);
    }
    async deleteUser(id, user) {
        return this.usersService.deleteUser(id, user);
    }
    me(user) {
        return user;
    }
};
exports.UsersController = UsersController;
__decorate([
    (0, common_1.UseInterceptors)(common_1.ClassSerializerInterceptor),
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Get)(':idOrEmail'),
    __param(0, (0, common_1.Param)('idOrEmail')),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "findOneUser", null);
__decorate([
    (0, common_1.UseInterceptors)(common_1.ClassSerializerInterceptor),
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Delete)(':id'),
    __param(0, (0, common_1.Param)('id', common_1.ParseUUIDPipe)),
    __param(1, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, typeof (_b = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _b : Object]),
    __metadata("design:returntype", Promise)
], UsersController.prototype, "deleteUser", null);
__decorate([
    (0, common_1.UseGuards)(roles_guard_1.RolesGuard),
    (0, decorators_1.Roles)(client_1.Role.ADMIN),
    (0, common_1.Get)(),
    __param(0, (0, decorators_1.CurrentUser)()),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [typeof (_c = typeof interfaces_1.JwtPayLoad !== "undefined" && interfaces_1.JwtPayLoad) === "function" ? _c : Object]),
    __metadata("design:returntype", void 0)
], UsersController.prototype, "me", null);
exports.UsersController = UsersController = __decorate([
    (0, common_1.Controller)('users'),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], UsersController);


/***/ }),

/***/ "./src/users/users.module.ts":
/*!***********************************!*\
  !*** ./src/users/users.module.ts ***!
  \***********************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersModule = void 0;
const cache_manager_1 = __webpack_require__(/*! @nestjs/cache-manager */ "@nestjs/cache-manager");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
const users_controller_1 = __webpack_require__(/*! ./users.controller */ "./src/users/users.controller.ts");
const users_service_1 = __webpack_require__(/*! ./users.service */ "./src/users/users.service.ts");
let UsersModule = class UsersModule {
};
exports.UsersModule = UsersModule;
exports.UsersModule = UsersModule = __decorate([
    (0, common_1.Module)({
        providers: [users_service_1.UsersService, prisma_service_1.PrismaService],
        exports: [users_service_1.UsersService],
        controllers: [users_controller_1.UsersController],
        imports: [cache_manager_1.CacheModule.register()]
    })
], UsersModule);


/***/ }),

/***/ "./src/users/users.service.ts":
/*!************************************!*\
  !*** ./src/users/users.service.ts ***!
  \************************************/
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
var _a, _b, _c;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.UsersService = void 0;
const utils_1 = __webpack_require__(/*! @common/common/utils */ "./libs/common/src/utils/index.ts");
const cache_manager_1 = __webpack_require__(/*! @nestjs/cache-manager */ "@nestjs/cache-manager");
const common_1 = __webpack_require__(/*! @nestjs/common */ "@nestjs/common");
const config_1 = __webpack_require__(/*! @nestjs/config */ "@nestjs/config");
const client_1 = __webpack_require__(/*! @prisma/client */ "@prisma/client");
const bcrypt_1 = __webpack_require__(/*! bcrypt */ "bcrypt");
const cache_manager_2 = __webpack_require__(/*! cache-manager */ "cache-manager");
const prisma_service_1 = __webpack_require__(/*! src/prisma/prisma.service */ "./src/prisma/prisma.service.ts");
let UsersService = class UsersService {
    constructor(prismaService, cacheManager, configService) {
        this.prismaService = prismaService;
        this.cacheManager = cacheManager;
        this.configService = configService;
    }
    async createUser(user) {
        const hashedPassword = this.hashPassword(user.password);
        return this.prismaService.user.create({
            data: {
                email: user.email,
                password: hashedPassword,
                roles: ['USER']
            }
        });
    }
    async findOne(idOrEmail, isReset = false) {
        if (isReset) {
            await this.cacheManager.del(idOrEmail);
        }
        const user = await this.cacheManager.get(idOrEmail);
        if (!user) {
            const user = await this.prismaService.user.findFirst({
                where: {
                    OR: [{ id: idOrEmail }, { email: idOrEmail }],
                },
            });
            if (!user) {
                return null;
            }
            await this.cacheManager.set(idOrEmail, user, (0, utils_1.convertToSecondsUtil)(this.configService.get('JWT_EXP')));
            return user;
        }
        return user;
    }
    async deleteUser(id, user) {
        if (user.id != id && !user.roles.includes(client_1.Role.ADMIN)) {
            throw new common_1.ForbiddenException();
        }
        await Promise.all([
            this.cacheManager.del(id),
            this.cacheManager.del(user.email)
        ]);
        return this.prismaService.user.delete({ where: { id }, select: { id: true } });
    }
    hashPassword(password) {
        return (0, bcrypt_1.hashSync)(password, (0, bcrypt_1.genSaltSync)(10));
    }
};
exports.UsersService = UsersService;
exports.UsersService = UsersService = __decorate([
    (0, common_1.Injectable)(),
    __param(1, (0, common_1.Inject)(cache_manager_1.CACHE_MANAGER)),
    __metadata("design:paramtypes", [typeof (_a = typeof prisma_service_1.PrismaService !== "undefined" && prisma_service_1.PrismaService) === "function" ? _a : Object, typeof (_b = typeof cache_manager_2.Cache !== "undefined" && cache_manager_2.Cache) === "function" ? _b : Object, typeof (_c = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _c : Object])
], UsersService);


/***/ }),

/***/ "@nestjs/cache-manager":
/*!****************************************!*\
  !*** external "@nestjs/cache-manager" ***!
  \****************************************/
/***/ ((module) => {

module.exports = require("@nestjs/cache-manager");

/***/ }),

/***/ "@nestjs/common":
/*!*********************************!*\
  !*** external "@nestjs/common" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/common");

/***/ }),

/***/ "@nestjs/config":
/*!*********************************!*\
  !*** external "@nestjs/config" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@nestjs/config");

/***/ }),

/***/ "@nestjs/core":
/*!*******************************!*\
  !*** external "@nestjs/core" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("@nestjs/core");

/***/ }),

/***/ "@nestjs/jwt":
/*!******************************!*\
  !*** external "@nestjs/jwt" ***!
  \******************************/
/***/ ((module) => {

module.exports = require("@nestjs/jwt");

/***/ }),

/***/ "@nestjs/passport":
/*!***********************************!*\
  !*** external "@nestjs/passport" ***!
  \***********************************/
/***/ ((module) => {

module.exports = require("@nestjs/passport");

/***/ }),

/***/ "@prisma/client":
/*!*********************************!*\
  !*** external "@prisma/client" ***!
  \*********************************/
/***/ ((module) => {

module.exports = require("@prisma/client");

/***/ }),

/***/ "bcrypt":
/*!*************************!*\
  !*** external "bcrypt" ***!
  \*************************/
/***/ ((module) => {

module.exports = require("bcrypt");

/***/ }),

/***/ "cache-manager":
/*!********************************!*\
  !*** external "cache-manager" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("cache-manager");

/***/ }),

/***/ "class-validator":
/*!**********************************!*\
  !*** external "class-validator" ***!
  \**********************************/
/***/ ((module) => {

module.exports = require("class-validator");

/***/ }),

/***/ "cookie-parser":
/*!********************************!*\
  !*** external "cookie-parser" ***!
  \********************************/
/***/ ((module) => {

module.exports = require("cookie-parser");

/***/ }),

/***/ "date-fns":
/*!***************************!*\
  !*** external "date-fns" ***!
  \***************************/
/***/ ((module) => {

module.exports = require("date-fns");

/***/ }),

/***/ "express":
/*!**************************!*\
  !*** external "express" ***!
  \**************************/
/***/ ((module) => {

module.exports = require("express");

/***/ }),

/***/ "node-cron":
/*!****************************!*\
  !*** external "node-cron" ***!
  \****************************/
/***/ ((module) => {

module.exports = require("node-cron");

/***/ }),

/***/ "passport-jwt":
/*!*******************************!*\
  !*** external "passport-jwt" ***!
  \*******************************/
/***/ ((module) => {

module.exports = require("passport-jwt");

/***/ }),

/***/ "uuid":
/*!***********************!*\
  !*** external "uuid" ***!
  \***********************/
/***/ ((module) => {

module.exports = require("uuid");

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;
/*!*********************!*\
  !*** ./src/main.ts ***!
  \*********************/

Object.defineProperty(exports, "__esModule", ({ value: true }));
const core_1 = __webpack_require__(/*! @nestjs/core */ "@nestjs/core");
const app_module_1 = __webpack_require__(/*! ./app.module */ "./src/app.module.ts");
const cookieParser = __webpack_require__(/*! cookie-parser */ "cookie-parser");
async function bootstrap() {
    const app = await core_1.NestFactory.create(app_module_1.AppModule);
    app.use(cookieParser());
    await app.listen(3001);
}
bootstrap();

})();

/******/ })()
;