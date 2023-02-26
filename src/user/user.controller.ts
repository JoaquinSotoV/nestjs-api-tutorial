import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { JwtGuard } from '../auth/guard'

@Controller('users')
export class UserController {
  @UseGuards(JwtGuard)
  @Get('me')
  getMe(@Req() req: Request) {
    return (<any>req).user
  }
}
