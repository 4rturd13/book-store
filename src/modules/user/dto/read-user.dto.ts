import { Exclude, Expose, Type } from 'class-transformer';
import { IsEmail, IsNumber } from 'class-validator';
import { ReadUserDetailsDto } from './read-user-details.dto';
import { ReadRoleDto } from '../../role/dtos/read-role.dto';

@Exclude()
export class ReadUserDto {
  @Expose()
  @IsNumber()
  readonly id: number;

  @Expose()
  @IsEmail()
  readonly email: string;

  @Expose()
  @IsEmail()
  readonly username: string;

  @Expose()
  @Type(type => ReadUserDetailsDto)
  readonly details: ReadUserDetailsDto;

  @Expose()
  @Type(type => ReadRoleDto)
  readonly roles: ReadRoleDto[];
}
